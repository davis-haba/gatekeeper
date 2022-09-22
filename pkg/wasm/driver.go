package wasm

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/dop251/goja"
	constraints2 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	target2 "github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/open-policy-agent/opa/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var root = flag.String("wasm-root", "~", "the root directory to search for WASM, defaults to homedir")

func NewDriver() *Driver {
	runJS, err := bootstrapJS()
	if err != nil {
		panic(err)
	}
	return &Driver{
		jsModules: make(map[string]string),
		runJS:     runJS,
	}
}

type Driver struct {
	jsModules map[string]string
	runJS     func(string, string, string) (string, error)
}

type WasmDecision struct {
	Decision   string
	Name       string
	Constraint *unstructured.Unstructured
}

var _ drivers.Driver = &Driver{}

func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {

	if len(ct.Spec.Targets) == 0 {
		return nil
	}

	jsCode := ct.Spec.Targets[0].Rego //JS

	if jsCode == "" {
		return nil
	}
	/// TODO: let's pretend this is just a string for now
	/// TODO: mutex
	d.jsModules[ct.Name] = jsCode
	return nil
}

func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	delete(d.jsModules, ct.Name)

	return nil
}

func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	jsModuleName := strings.ToLower(constraint.GetKind())

	_, found := d.jsModules[jsModuleName]
	if !found {
		return fmt.Errorf("no wasmModuleName with name: %q", jsModuleName)
	}

	return nil
}

func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	return nil
}

func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	return nil
}

func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
	return nil
}

func bootstrapJS() (func(string, string, string) (string, error), error) {
	vm := goja.New()

	return func(code, data, params string) (string, error) {
		_, err := vm.RunString(code)
		if err != nil {
			panic(fmt.Sprintf("error loading js code: %s", err))
		}
		policyFn, ok := goja.AssertFunction(vm.Get("policy"))
		if !ok {
			panic("policy func not found in js code")
		}
		res, err := policyFn(goja.Undefined(), vm.ToValue(data), vm.ToValue(params))
		if err != nil {
			panic(fmt.Sprintf("error running policyFn: %s", err))
		}

		return fmt.Sprintf("%s", res.ToString()), err
	}, nil
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {

	gkr := review.(*target2.GkReview)

	obj := &unstructured.Unstructured{
		Object: make(map[string]interface{}),
	}

	err := obj.UnmarshalJSON(gkr.Object.Raw)
	if err != nil {
		return nil, nil, err
	}

	var allDecisions []*WasmDecision
	for _, constraint := range constraints {
		jsModule, found := d.jsModules[strings.ToLower(constraint.GetKind())]
		if !found {
			continue
		}

		paramsStruct, _, err := unstructured.NestedFieldNoCopy(constraint.Object, "spec", "parameters")
		if err != nil {
			return nil, nil, err
		}

		params, err := json.Marshal(paramsStruct)
		if err != nil {
			return nil, nil, err
		}

		// pass in object as os.Args[1]
		fmt.Printf("gkr: %s\n", gkr)
		fmt.Printf("gkrobject: %s\n", gkr.Object)
		fmt.Printf("gkrobjectraw: %s\n", gkr.Object.Raw)
		results, err := d.runJS(jsModule, string(gkr.Object.Raw), string(params))
		if err != nil {
			return nil, nil, err
		}

		wasmDecision := &WasmDecision{
			Decision:   results,
			Name:       constraint.GetName(),
			Constraint: constraint,
		}

		allDecisions = append(allDecisions, wasmDecision)
	}
	if len(allDecisions) == 0 {
		return nil, nil, nil
	}

	results := make([]*types.Result, len(allDecisions))
	for i, wasmDecision := range allDecisions {
		enforcementAction, found, err := unstructured.NestedString(wasmDecision.Constraint.Object, "spec", "enforcementAction")
		if err != nil {
			return nil, nil, err
		}
		if !found {
			enforcementAction = constraints2.EnforcementActionDeny
		}

		results[i] = &types.Result{
			Metadata: map[string]interface{}{
				"name": wasmDecision.Name,
			},
			Constraint:        wasmDecision.Constraint,
			Msg:               string(wasmDecision.Decision),
			EnforcementAction: enforcementAction,
		}
	}

	return results, nil, nil
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}

func readToEnd(w io.Writer, b io.Reader) (string, error) {
	data := make([]byte, 256)
	var builder strings.Builder
	extra := 0
	for {
		l, err := b.Read(data)
		if err != nil {
			return "", err
		}
		if l < 0 {
			return "", errors.New("negative reader read")
		}
		builder.Write(data[:l])
		if l < len(data) {
			break
		}
		// add an extra byte in case we reached the exact end of the buffer
		// otherwise the next read blocks indefinitely
		if l == len(data) {
			extra++
			n, err := w.Write([]byte("+"))
			if err != nil {
				return "", err
			}
			if n != 1 {
				return "", errors.New("could not write extra byte")
			}
		}
	}
	val := builder.String()

	return val[:len(val)-extra], nil
}
