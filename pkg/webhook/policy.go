/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1alpha1"
	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	rtypes "github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/gatekeeper/apis"
	mutationsunversioned "github.com/open-policy-agent/gatekeeper/apis/mutations/unversioned"
	"github.com/open-policy-agent/gatekeeper/pkg/controller/config/process"
	"github.com/open-policy-agent/gatekeeper/pkg/expansion"
	"github.com/open-policy-agent/gatekeeper/pkg/keys"
	"github.com/open-policy-agent/gatekeeper/pkg/logging"
	"github.com/open-policy-agent/gatekeeper/pkg/mutation"
	"github.com/open-policy-agent/gatekeeper/pkg/mutation/mutators/assign"
	"github.com/open-policy-agent/gatekeeper/pkg/mutation/mutators/assignmeta"
	"github.com/open-policy-agent/gatekeeper/pkg/mutation/mutators/modifyset"
	mutationtypes "github.com/open-policy-agent/gatekeeper/pkg/mutation/types"
	"github.com/open-policy-agent/gatekeeper/pkg/operations"
	"github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/open-policy-agent/gatekeeper/pkg/util"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// httpStatusWarning is the HTTP return code for displaying warning messages in admission webhook (supported in Kubernetes v1.19+)
// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#response
const httpStatusWarning = 299

var maxServingThreads = flag.Int("max-serving-threads", -1, "cap the number of threads handling non-trivial requests, -1 caps the number of threads to GOMAXPROCS. Defaults to -1.")

func init() {
	AddToManagerFuncs = append(AddToManagerFuncs, AddPolicyWebhook)
	if err := apis.AddToScheme(runtimeScheme); err != nil {
		log.Error(err, "unable to add to scheme")
		panic(err)
	}
}

// Explicitly list all known subresources except "status" (to avoid destabilizing the cluster and increasing load on gatekeeper). But include "services/status" for constraints that mitigate CVE-2020-8554.
// You can find a rough list of subresources by doing a case-sensitive search in the Kubernetes codebase for 'Subresource("'
// +kubebuilder:webhook:verbs=create;update,path=/v1/admit,mutating=false,failurePolicy=ignore,groups=*,resources=*;pods/ephemeralcontainers;pods/exec;pods/log;pods/eviction;pods/portforward;pods/proxy;pods/attach;pods/binding;deployments/scale;replicasets/scale;statefulsets/scale;replicationcontrollers/scale;services/proxy;nodes/proxy;services/status,versions=*,name=validation.gatekeeper.sh,sideEffects=None,admissionReviewVersions=v1;v1beta1,matchPolicy=Exact
// +kubebuilder:rbac:groups=*,resources=*,verbs=get;list;watch

// AddPolicyWebhook registers the policy webhook server with the manager.
func AddPolicyWebhook(mgr manager.Manager, deps Dependencies) error {
	if !operations.IsAssigned(operations.Webhook) {
		return nil
	}
	reporter, err := newStatsReporter()
	if err != nil {
		return err
	}
	eventBroadcaster := record.NewBroadcaster()
	kubeClient := kubernetes.NewForConfigOrDie(mgr.GetConfig())
	eventBroadcaster.StartRecordingToSink(&clientcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(
		scheme.Scheme,
		corev1.EventSource{Component: "gatekeeper-webhook"})
	handler := &validationHandler{
		opa:             deps.OpaClient,
		mutationSystem:  deps.MutationSystem,
		expansionSystem: deps.ExpansionSystem,
		webhookHandler: webhookHandler{
			client:          mgr.GetClient(),
			reader:          mgr.GetAPIReader(),
			reporter:        reporter,
			processExcluder: deps.ProcessExcluder,
			eventRecorder:   recorder,
			gkNamespace:     util.GetNamespace(),
		},
	}
	threadCount := *maxServingThreads
	if threadCount < 1 {
		threadCount = runtime.GOMAXPROCS(-1)
	}
	handler.semaphore = make(chan struct{}, threadCount)
	wh := &admission.Webhook{Handler: handler}
	// TODO(https://github.com/open-policy-agent/gatekeeper/issues/661): remove log injection if the race condition in the cited bug is eliminated.
	// Otherwise we risk having unstable logger names for the webhook.
	if err := wh.InjectLogger(log); err != nil {
		return err
	}
	server := mgr.GetWebhookServer()
	server.TLSMinVersion = *tlsMinVersion
	server.Register("/v1/admit", wh)
	return nil
}

var _ admission.Handler = &validationHandler{}

type validationHandler struct {
	webhookHandler
	opa             *constraintclient.Client
	mutationSystem  *mutation.System
	expansionSystem *expansion.System
	semaphore       chan struct{}
}

// Handle the validation request
// nolint: gocritic // Must accept admission.Request as a struct to satisfy Handler interface.
func (h *validationHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := log.WithValues("hookType", "validation")

	timeStart := time.Now()

	if isGkServiceAccount(req.AdmissionRequest.UserInfo) {
		return admission.Allowed("Gatekeeper does not self-manage")
	}

	if req.AdmissionRequest.Operation == admissionv1.Delete {
		// oldObject is the existing object.
		// It is null for DELETE operations in API servers prior to v1.15.0.
		// https://github.com/kubernetes/website/pull/14671
		if req.AdmissionRequest.OldObject.Raw == nil {
			vResp := admission.Denied("For admission webhooks registered for DELETE operations, please use Kubernetes v1.15.0+.")
			vResp.Result.Code = http.StatusInternalServerError
			return vResp
		}
		// For admission webhooks registered for DELETE operations on k8s built APIs or CRDs,
		// the apiserver now sends the existing object as admissionRequest.Request.OldObject to the webhook
		// object is the new object being admitted.
		// It is null for DELETE operations.
		// https://github.com/kubernetes/kubernetes/pull/76346
		req.AdmissionRequest.Object = req.AdmissionRequest.OldObject
	}

	if userErr, err := h.validateGatekeeperResources(ctx, &req); err != nil {
		var code int32
		if userErr {
			code = http.StatusUnprocessableEntity
		} else {
			code = http.StatusInternalServerError
		}
		return admission.Errored(code, err)
	}

	requestResponse := unknownResponse
	defer func() {
		if h.reporter != nil {
			if err := h.reporter.ReportValidationRequest(ctx, requestResponse, time.Since(timeStart)); err != nil {
				log.Error(err, "failed to report request")
			}
		}
	}()

	// namespace is excluded from webhook using config
	isExcludedNamespace, err := h.skipExcludedNamespace(&req.AdmissionRequest, process.Webhook)
	if err != nil {
		log.Error(err, "error while excluding namespace")
	}

	if isExcludedNamespace {
		requestResponse = allowResponse
		return admission.Allowed("Namespace is set to be ignored by Gatekeeper config")
	}

	resp, err := h.reviewRequest(ctx, &req)
	if err != nil {
		log.Error(err, "error executing query")
		requestResponse = errorResponse
		return admission.Errored(http.StatusInternalServerError, err)
	}

	res := resp.Results()
	denyMsgs, warnMsgs := h.getValidationMessages(res, &req)

	if len(denyMsgs) > 0 {
		requestResponse = denyResponse
		return admission.Response{
			AdmissionResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Reason:  metav1.StatusReasonForbidden,
					Code:    http.StatusForbidden,
					Message: strings.Join(denyMsgs, "\n"),
				},
				Warnings: warnMsgs,
			},
		}
	}

	requestResponse = allowResponse
	vResp := admission.Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Code: http.StatusOK,
			},
			Warnings: warnMsgs,
		},
	}
	if len(warnMsgs) > 0 {
		vResp.Result.Code = httpStatusWarning
	}
	return vResp
}

func (h *validationHandler) getValidationMessages(res []*rtypes.Result, req *admission.Request) ([]string, []string) {
	var denyMsgs, warnMsgs []string
	var resourceName string
	if len(res) > 0 && (*logDenies || *emitAdmissionEvents) {
		resourceName = req.AdmissionRequest.Name
		if len(resourceName) == 0 && req.AdmissionRequest.Object.Raw != nil {
			// On a CREATE operation, the client may omit name and
			// rely on the server to generate the name.
			obj := &unstructured.Unstructured{}
			if _, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, obj); err == nil {
				resourceName = obj.GetName()
			}
		}
	}
	for _, r := range res {
		if err := util.ValidateEnforcementAction(util.EnforcementAction(r.EnforcementAction)); err != nil {
			continue
		}
		if *logDenies {
			log.WithValues(
				logging.Process, "admission",
				logging.EventType, "violation",
				logging.ConstraintName, r.Constraint.GetName(),
				logging.ConstraintGroup, r.Constraint.GroupVersionKind().Group,
				logging.ConstraintAPIVersion, r.Constraint.GroupVersionKind().Version,
				logging.ConstraintKind, r.Constraint.GetKind(),
				logging.ConstraintAction, r.EnforcementAction,
				logging.ResourceGroup, req.AdmissionRequest.Kind.Group,
				logging.ResourceAPIVersion, req.AdmissionRequest.Kind.Version,
				logging.ResourceKind, req.AdmissionRequest.Kind.Kind,
				logging.ResourceNamespace, req.AdmissionRequest.Namespace,
				logging.ResourceName, resourceName,
				logging.RequestUsername, req.AdmissionRequest.UserInfo.Username,
			).Info("denied admission")
		}
		if *emitAdmissionEvents {
			annotations := map[string]string{
				logging.Process:              "admission",
				logging.EventType:            "violation",
				logging.ConstraintName:       r.Constraint.GetName(),
				logging.ConstraintGroup:      r.Constraint.GroupVersionKind().Group,
				logging.ConstraintAPIVersion: r.Constraint.GroupVersionKind().Version,
				logging.ConstraintKind:       r.Constraint.GetKind(),
				logging.ConstraintAction:     r.EnforcementAction,
				logging.ResourceGroup:        req.AdmissionRequest.Kind.Group,
				logging.ResourceAPIVersion:   req.AdmissionRequest.Kind.Version,
				logging.ResourceKind:         req.AdmissionRequest.Kind.Kind,
				logging.ResourceNamespace:    req.AdmissionRequest.Namespace,
				logging.ResourceName:         resourceName,
				logging.RequestUsername:      req.AdmissionRequest.UserInfo.Username,
			}
			var eventMsg, reason string
			switch r.EnforcementAction {
			case string(util.Dryrun):
				eventMsg = "Dryrun violation"
				reason = "DryrunViolation"
			case string(util.Warn):
				eventMsg = "Admission webhook \"validation.gatekeeper.sh\" raised a warning for this request"
				reason = "WarningAdmission"
			default:
				eventMsg = "Admission webhook \"validation.gatekeeper.sh\" denied request"
				reason = "FailedAdmission"
			}
			ref := getViolationRef(
				h.gkNamespace,
				req.AdmissionRequest.Kind.Kind,
				resourceName,
				req.AdmissionRequest.Namespace,
				r.Constraint.GetKind(),
				r.Constraint.GetName(),
				r.Constraint.GetNamespace())
			h.eventRecorder.AnnotatedEventf(
				ref,
				annotations,
				corev1.EventTypeWarning,
				reason,
				"%s, Resource Namespace: %s, Constraint: %s, Message: %s",
				eventMsg,
				req.AdmissionRequest.Namespace,
				r.Constraint.GetName(),
				r.Msg)
		}

		if r.EnforcementAction == string(util.Deny) {
			denyMsgs = append(denyMsgs, fmt.Sprintf("[%s] %s", r.Constraint.GetName(), r.Msg))
		}

		if r.EnforcementAction == string(util.Warn) {
			warnMsgs = append(warnMsgs, fmt.Sprintf("[%s] %s", r.Constraint.GetName(), r.Msg))
		}
	}
	return denyMsgs, warnMsgs
}

// validateGatekeeperResources returns whether an issue is user error (vs internal) and any errors
// validating internal resources.
func (h *validationHandler) validateGatekeeperResources(ctx context.Context, req *admission.Request) (bool, error) {
	gvk := req.AdmissionRequest.Kind

	switch {
	case gvk.Group == "templates.gatekeeper.sh" && gvk.Kind == "ConstraintTemplate":
		return h.validateTemplate(ctx, req)
	case gvk.Group == "constraints.gatekeeper.sh":
		return h.validateConstraint(req)
	case gvk.Group == "config.gatekeeper.sh" && gvk.Kind == "Config":
		if err := h.validateConfigResource(req); err != nil {
			return true, err
		}
	case req.AdmissionRequest.Kind.Group == mutationsGroup && req.AdmissionRequest.Kind.Kind == "AssignMetadata":
		return h.validateAssignMetadata(req)
	case req.AdmissionRequest.Kind.Group == mutationsGroup && req.AdmissionRequest.Kind.Kind == "Assign":
		return h.validateAssign(req)
	case req.AdmissionRequest.Kind.Group == mutationsGroup && req.AdmissionRequest.Kind.Kind == "ModifySet":
		return h.validateModifySet(req)
	case req.AdmissionRequest.Kind.Group == externalDataGroup && req.AdmissionRequest.Kind.Kind == "Provider":
		return h.validateProvider(req)
		// TODO add case here to validate ExpansionTemplate
	}

	return false, nil
}

// validateTemplate validates the ConstraintTemplate in the Request.
// Returns an error if the ConstraintTemplate fails validation.
// The returned boolean is only true if error is non-nil and is a result of user
// error.
func (h *validationHandler) validateTemplate(ctx context.Context, req *admission.Request) (bool, error) {
	templ, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, nil)
	if err != nil {
		return false, err
	}

	unversioned := &templates.ConstraintTemplate{}
	err = runtimeScheme.Convert(templ, unversioned, nil)
	if err != nil {
		return false, err
	}

	// Ensure that it is possible to generate a CRD for this ConstraintTemplate.
	_, err = h.opa.CreateCRD(ctx, unversioned)
	if err != nil {
		return true, err
	}

	// Create a temporary Driver and attempt to add the Template to it. This
	// ensures the Rego code both parses and compiles.
	d, err := local.New()
	if err != nil {
		return false, fmt.Errorf("unable to create Driver: %v", err)
	}

	err = d.AddTemplate(ctx, unversioned)
	if err != nil {
		return true, err
	}

	return false, nil
}

func (h *validationHandler) validateConstraint(req *admission.Request) (bool, error) {
	obj := &unstructured.Unstructured{}
	if _, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, obj); err != nil {
		return false, err
	}
	if err := h.opa.ValidateConstraint(obj); err != nil {
		return true, err
	}

	enforcementActionString, found, err := unstructured.NestedString(obj.Object, "spec", "enforcementAction")
	if err != nil {
		return false, err
	}
	enforcementAction := util.EnforcementAction(enforcementActionString)
	if found && enforcementAction != "" {
		if !*disableEnforcementActionValidation {
			err = util.ValidateEnforcementAction(enforcementAction)
			if err != nil {
				return false, err
			}
		}
	} else {
		return true, nil
	}
	return false, nil
}

func (h *validationHandler) validateConfigResource(req *admission.Request) error {
	if req.Name != keys.Config.Name {
		return fmt.Errorf("config resource must have name 'config'")
	}
	return nil
}

func (h *validationHandler) validateAssignMetadata(req *admission.Request) (bool, error) {
	obj, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, nil)
	if err != nil {
		return false, err
	}
	unversioned := &mutationsunversioned.AssignMetadata{}
	if err := runtimeScheme.Convert(obj, unversioned, nil); err != nil {
		return false, err
	}
	err = assignmeta.IsValidAssignMetadata(unversioned)
	if err != nil {
		return true, err
	}

	return false, nil
}

func (h *validationHandler) validateAssign(req *admission.Request) (bool, error) {
	obj, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, nil)
	if err != nil {
		return false, err
	}
	unversioned := &mutationsunversioned.Assign{}
	if err := runtimeScheme.Convert(obj, unversioned, nil); err != nil {
		return false, err
	}
	err = assign.IsValidAssign(unversioned)
	if err != nil {
		return true, err
	}

	return false, nil
}

func (h *validationHandler) validateModifySet(req *admission.Request) (bool, error) {
	obj, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, nil)
	if err != nil {
		return false, err
	}
	unversioned := &mutationsunversioned.ModifySet{}
	if err := runtimeScheme.Convert(obj, unversioned, nil); err != nil {
		return false, err
	}
	err = modifyset.IsValidModifySet(unversioned)
	if err != nil {
		return true, err
	}

	return false, nil
}

func (h *validationHandler) validateProvider(req *admission.Request) (bool, error) {
	obj, _, err := deserializer.Decode(req.AdmissionRequest.Object.Raw, nil, nil)
	if err != nil {
		return false, err
	}
	provider := &v1alpha1.Provider{}
	if err := runtimeScheme.Convert(obj, provider, nil); err != nil {
		return false, err
	}

	// Ensure that it is possible to insert the Provider into the cache.
	cache := externaldata.NewCache()
	if err := cache.Upsert(provider); err != nil {
		return true, err
	}
	return false, nil
}

// traceSwitch returns true if a request should be traced.
func (h *validationHandler) reviewRequest(ctx context.Context, req *admission.Request) (*rtypes.Responses, error) {
	// if we have a maximum number of concurrent serving goroutines, try to acquire
	// a lock and block until we succeed
	if h.semaphore != nil {
		select {
		case h.semaphore <- struct{}{}:
			defer func() {
				<-h.semaphore
			}()
		case <-ctx.Done():
			return nil, errors.New("serving context canceled, aborting request")
		}
	}

	review, err := h.createReviewForRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create augmentedReview: %s", err)
	}

	// Convert the request's generator resource to unstructured for expansion
	obj := &unstructured.Unstructured{}
	if _, _, err := deserializer.Decode(req.Object.Raw, nil, obj); err != nil {
		return nil, fmt.Errorf("error decoding generator resource %s: %v", req.Name, err)
	}
	obj.SetNamespace(req.Namespace)
	obj.SetGroupVersionKind(
		schema.GroupVersionKind{
			Group:   req.Kind.Group,
			Version: req.Kind.Version,
			Kind:    req.Kind.Kind,
		})

	// Expand the generator and apply mutators to the resultant resources
	base := &mutationtypes.Mutable{
		Object:    obj,
		Namespace: review.Namespace,
		Username:  req.AdmissionRequest.UserInfo.Username,
		Source:    mutationtypes.SourceTypeGenerated,
	}
	resultants, err := h.expansionSystem.Expand(base)
	if err != nil {
		return nil, fmt.Errorf("error expanding generator: %s", err)
	}

	trace, dump := h.tracingLevel(ctx, req)
	resp, err := h.review(ctx, review, trace, dump)
	if err != nil {
		return nil, fmt.Errorf("error reviewing resource %s: %s", req.Name, err)
	}

	var resultantResps []*rtypes.Responses
	for _, res := range resultants {
		resp, err := h.review(ctx, createReviewForResultant(res, review.Namespace), trace, dump)
		if err != nil {
			return nil, fmt.Errorf("error reviewing resultant resource: %s", err)
		}
		resultantResps = append(resultantResps, resp)
	}
	expansion.AggregateResponses(req.Name, resp, resultantResps)

	return resp, nil
}

func (h *validationHandler) review(ctx context.Context, review interface{}, trace bool, dump bool) (*rtypes.Responses, error) {
	resp, err := h.opa.Review(ctx, review, drivers.Tracing(trace))
	if resp != nil && trace {
		log.Info(resp.TraceDump())
	}
	if dump {
		dump, err := h.opa.Dump(ctx)
		if err != nil {
			log.Error(err, "dump error")
		} else {
			log.Info(dump)
		}
	}

	return resp, err
}

func (h *validationHandler) createReviewForRequest(ctx context.Context, req *admission.Request) (*target.AugmentedReview, error) {
	// Coerce server-side apply admission requests into treating namespaces
	// the same way as older admission requests. See
	// https://github.com/open-policy-agent/gatekeeper/issues/792
	if req.Kind.Kind == namespaceKind && req.Kind.Group == "" {
		req.Namespace = ""
	}
	review := &target.AugmentedReview{
		AdmissionRequest: &req.AdmissionRequest,
		Source:           mutationtypes.SourceTypeOriginal,
	}
	if req.AdmissionRequest.Namespace != "" {
		ns := &corev1.Namespace{}
		if err := h.client.Get(ctx, types.NamespacedName{Name: req.AdmissionRequest.Namespace}, ns); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, err
			}
			// bypass cached client and ask api-server directly
			err = h.reader.Get(ctx, types.NamespacedName{Name: req.AdmissionRequest.Namespace}, ns)
			if err != nil {
				return nil, err
			}
		}
		review.Namespace = ns
	}

	return review, nil
}

func createReviewForResultant(obj *unstructured.Unstructured, ns *corev1.Namespace) *target.AugmentedUnstructured {
	return &target.AugmentedUnstructured{
		Object:    *obj,
		Namespace: ns,
		Source:    mutationtypes.SourceTypeGenerated,
	}
}

func getViolationRef(gkNamespace, rkind, rname, rnamespace, ckind, cname, cnamespace string) *corev1.ObjectReference {
	return &corev1.ObjectReference{
		Kind:      rkind,
		Name:      rname,
		UID:       types.UID(rkind + "/" + rnamespace + "/" + rname + "/" + ckind + "/" + cnamespace + "/" + cname),
		Namespace: gkNamespace,
	}
}

func AppendValidationWebhookIfEnabled(webhooks []rotator.WebhookInfo) []rotator.WebhookInfo {
	if operations.IsAssigned(operations.Webhook) {
		return append(webhooks, rotator.WebhookInfo{
			Name: VwhName,
			Type: rotator.Validating,
		})
	}
	return webhooks
}
