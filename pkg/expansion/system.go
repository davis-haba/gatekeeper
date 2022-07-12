package expansion

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	expansionunversioned "github.com/open-policy-agent/gatekeeper/apis/expansion/unversioned"
	"github.com/open-policy-agent/gatekeeper/apis/expansion/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type System struct {
	lock      sync.Mutex
	templates map[string]*expansionunversioned.TemplateExpansion
}

func keyForTemplate(template *expansionunversioned.TemplateExpansion) string {
	return template.ObjectMeta.Name
}

func (s *System) UpsertTemplate(template *expansionunversioned.TemplateExpansion) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	k := keyForTemplate(template)
	if k == "" {
		return fmt.Errorf("cannot upsert template with empty name")
	}

	s.templates[k] = template.DeepCopy()
	return nil
}

func (s *System) RemoveTemplate(template *expansionunversioned.TemplateExpansion) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	k := keyForTemplate(template)
	if k == "" {
		return fmt.Errorf("cannot remove template with empty name")
	}

	delete(s.templates, k)
	return nil
}

func sourcePath(source string) []string {
	return strings.Split(source, ".")
}

func prettyResource(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		return string(b) + "\n"
	}
	return ""
}

func genGVKToSchemaGVK(gvk expansionunversioned.GeneratedGVK) schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   gvk.Group,
		Version: gvk.Version,
		Kind:    gvk.Kind,
	}
}

// TemplatesForGVK returns a slice of TemplateExpansions that match a given gvk.
func (s *System) TemplatesForGVK(gvk schema.GroupVersionKind) []*expansionunversioned.TemplateExpansion {
	s.lock.Lock()
	defer s.lock.Unlock()

	var templates []*expansionunversioned.TemplateExpansion
	for _, t := range s.templates {
		for _, apply := range t.Spec.ApplyTo {
			if apply.Matches(gvk) {
				templates = append(templates, t)
			}
		}
	}

	return templates
}

func (s *System) ExpandGenerator(generator *unstructured.Unstructured, templates []*expansionunversioned.TemplateExpansion) ([]*unstructured.Unstructured, error) {
	var resultants []*unstructured.Unstructured

	for _, te := range templates {
		res, err := expand(generator, te)
		resultants = append(resultants, res)
		if err != nil {
			return nil, err
		}
	}

	return resultants, nil
}

func expand(generator *unstructured.Unstructured, template *expansionunversioned.TemplateExpansion) (*unstructured.Unstructured, error) {
	srcPath := template.Spec.TemplateSource
	if srcPath == "" {
		return nil, fmt.Errorf("cannot expand generator for template with no source")
	}
	resultantGVK := genGVKToSchemaGVK(template.Spec.GeneratedGVK)
	emptyGVK := schema.GroupVersionKind{}
	if resultantGVK == emptyGVK {
		return nil, fmt.Errorf("cannot expand generator for template with empty generatedGVK")
	}

	src, ok, err := unstructured.NestedMap(generator.Object, sourcePath(srcPath)...)
	if err != nil {
		return nil, fmt.Errorf("could not extract source field from unstructured: %s", err)
	}
	if !ok {
		return nil, fmt.Errorf("could not find source field %q in generator", srcPath)
	}

	resource := &unstructured.Unstructured{}
	resource.SetUnstructuredContent(src)
	resource.SetGroupVersionKind(resultantGVK)

	return resource, nil
}

func NewSystem() *System {
	return &System{
		lock:      sync.Mutex{},
		templates: map[string]*expansionunversioned.TemplateExpansion{},
	}
}

func V1Alpha1TemplateToUnversioned(expansion *v1alpha1.TemplateExpansion) *expansionunversioned.TemplateExpansion {
	return &expansionunversioned.TemplateExpansion{
		TypeMeta:   expansion.TypeMeta,
		ObjectMeta: expansion.ObjectMeta,
		Spec: expansionunversioned.TemplateExpansionSpec{
			ApplyTo:        expansion.Spec.ApplyTo,
			TemplateSource: expansion.Spec.TemplateSource,
			GeneratedGVK: expansionunversioned.GeneratedGVK{
				Group:   expansion.Spec.GeneratedGVK.Group,
				Version: expansion.Spec.GeneratedGVK.Version,
				Kind:    expansion.Spec.GeneratedGVK.Kind,
			},
		},
		Status: expansionunversioned.TemplateExpansionStatus{},
	}
}
