//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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
// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	unversioned "github.com/open-policy-agent/gatekeeper/apis/expansion/unversioned"
	match "github.com/open-policy-agent/gatekeeper/pkg/mutation/match"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*GeneratedGVK)(nil), (*unversioned.GeneratedGVK)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_GeneratedGVK_To_unversioned_GeneratedGVK(a.(*GeneratedGVK), b.(*unversioned.GeneratedGVK), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*unversioned.GeneratedGVK)(nil), (*GeneratedGVK)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_unversioned_GeneratedGVK_To_v1alpha1_GeneratedGVK(a.(*unversioned.GeneratedGVK), b.(*GeneratedGVK), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*ExpansionTemplate)(nil), (*unversioned.ExpansionTemplate)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ExpansionTemplate_To_unversioned_ExpansionTemplate(a.(*ExpansionTemplate), b.(*unversioned.ExpansionTemplate), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*unversioned.ExpansionTemplate)(nil), (*ExpansionTemplate)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_unversioned_ExpansionTemplate_To_v1alpha1_ExpansionTemplate(a.(*unversioned.ExpansionTemplate), b.(*ExpansionTemplate), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*ExpansionTemplateList)(nil), (*unversioned.ExpansionTemplateList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ExpansionTemplateList_To_unversioned_ExpansionTemplateList(a.(*ExpansionTemplateList), b.(*unversioned.ExpansionTemplateList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*unversioned.ExpansionTemplateList)(nil), (*ExpansionTemplateList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_unversioned_ExpansionTemplateList_To_v1alpha1_ExpansionTemplateList(a.(*unversioned.ExpansionTemplateList), b.(*ExpansionTemplateList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*ExpansionTemplateSpec)(nil), (*unversioned.ExpansionTemplateSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ExpansionTemplateSpec_To_unversioned_ExpansionTemplateSpec(a.(*ExpansionTemplateSpec), b.(*unversioned.ExpansionTemplateSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*unversioned.ExpansionTemplateSpec)(nil), (*ExpansionTemplateSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_unversioned_ExpansionTemplateSpec_To_v1alpha1_ExpansionTemplateSpec(a.(*unversioned.ExpansionTemplateSpec), b.(*ExpansionTemplateSpec), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_GeneratedGVK_To_unversioned_GeneratedGVK(in *GeneratedGVK, out *unversioned.GeneratedGVK, s conversion.Scope) error {
	out.Group = in.Group
	out.Version = in.Version
	out.Kind = in.Kind
	return nil
}

// Convert_v1alpha1_GeneratedGVK_To_unversioned_GeneratedGVK is an autogenerated conversion function.
func Convert_v1alpha1_GeneratedGVK_To_unversioned_GeneratedGVK(in *GeneratedGVK, out *unversioned.GeneratedGVK, s conversion.Scope) error {
	return autoConvert_v1alpha1_GeneratedGVK_To_unversioned_GeneratedGVK(in, out, s)
}

func autoConvert_unversioned_GeneratedGVK_To_v1alpha1_GeneratedGVK(in *unversioned.GeneratedGVK, out *GeneratedGVK, s conversion.Scope) error {
	out.Group = in.Group
	out.Version = in.Version
	out.Kind = in.Kind
	return nil
}

// Convert_unversioned_GeneratedGVK_To_v1alpha1_GeneratedGVK is an autogenerated conversion function.
func Convert_unversioned_GeneratedGVK_To_v1alpha1_GeneratedGVK(in *unversioned.GeneratedGVK, out *GeneratedGVK, s conversion.Scope) error {
	return autoConvert_unversioned_GeneratedGVK_To_v1alpha1_GeneratedGVK(in, out, s)
}

func autoConvert_v1alpha1_ExpansionTemplate_To_unversioned_ExpansionTemplate(in *ExpansionTemplate, out *unversioned.ExpansionTemplate, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_ExpansionTemplateSpec_To_unversioned_ExpansionTemplateSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_ExpansionTemplate_To_unversioned_ExpansionTemplate is an autogenerated conversion function.
func Convert_v1alpha1_ExpansionTemplate_To_unversioned_ExpansionTemplate(in *ExpansionTemplate, out *unversioned.ExpansionTemplate, s conversion.Scope) error {
	return autoConvert_v1alpha1_ExpansionTemplate_To_unversioned_ExpansionTemplate(in, out, s)
}

func autoConvert_unversioned_ExpansionTemplate_To_v1alpha1_ExpansionTemplate(in *unversioned.ExpansionTemplate, out *ExpansionTemplate, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_unversioned_ExpansionTemplateSpec_To_v1alpha1_ExpansionTemplateSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_unversioned_ExpansionTemplate_To_v1alpha1_ExpansionTemplate is an autogenerated conversion function.
func Convert_unversioned_ExpansionTemplate_To_v1alpha1_ExpansionTemplate(in *unversioned.ExpansionTemplate, out *ExpansionTemplate, s conversion.Scope) error {
	return autoConvert_unversioned_ExpansionTemplate_To_v1alpha1_ExpansionTemplate(in, out, s)
}

func autoConvert_v1alpha1_ExpansionTemplateList_To_unversioned_ExpansionTemplateList(in *ExpansionTemplateList, out *unversioned.ExpansionTemplateList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]unversioned.ExpansionTemplate)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_ExpansionTemplateList_To_unversioned_ExpansionTemplateList is an autogenerated conversion function.
func Convert_v1alpha1_ExpansionTemplateList_To_unversioned_ExpansionTemplateList(in *ExpansionTemplateList, out *unversioned.ExpansionTemplateList, s conversion.Scope) error {
	return autoConvert_v1alpha1_ExpansionTemplateList_To_unversioned_ExpansionTemplateList(in, out, s)
}

func autoConvert_unversioned_ExpansionTemplateList_To_v1alpha1_ExpansionTemplateList(in *unversioned.ExpansionTemplateList, out *ExpansionTemplateList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]ExpansionTemplate)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_unversioned_ExpansionTemplateList_To_v1alpha1_ExpansionTemplateList is an autogenerated conversion function.
func Convert_unversioned_ExpansionTemplateList_To_v1alpha1_ExpansionTemplateList(in *unversioned.ExpansionTemplateList, out *ExpansionTemplateList, s conversion.Scope) error {
	return autoConvert_unversioned_ExpansionTemplateList_To_v1alpha1_ExpansionTemplateList(in, out, s)
}

func autoConvert_v1alpha1_ExpansionTemplateSpec_To_unversioned_ExpansionTemplateSpec(in *ExpansionTemplateSpec, out *unversioned.ExpansionTemplateSpec, s conversion.Scope) error {
	out.ApplyTo = *(*[]match.ApplyTo)(unsafe.Pointer(&in.ApplyTo))
	out.TemplateSource = in.TemplateSource
	if err := Convert_v1alpha1_GeneratedGVK_To_unversioned_GeneratedGVK(&in.GeneratedGVK, &out.GeneratedGVK, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_ExpansionTemplateSpec_To_unversioned_ExpansionTemplateSpec is an autogenerated conversion function.
func Convert_v1alpha1_ExpansionTemplateSpec_To_unversioned_ExpansionTemplateSpec(in *ExpansionTemplateSpec, out *unversioned.ExpansionTemplateSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_ExpansionTemplateSpec_To_unversioned_ExpansionTemplateSpec(in, out, s)
}

func autoConvert_unversioned_ExpansionTemplateSpec_To_v1alpha1_ExpansionTemplateSpec(in *unversioned.ExpansionTemplateSpec, out *ExpansionTemplateSpec, s conversion.Scope) error {
	out.ApplyTo = *(*[]match.ApplyTo)(unsafe.Pointer(&in.ApplyTo))
	out.TemplateSource = in.TemplateSource
	if err := Convert_unversioned_GeneratedGVK_To_v1alpha1_GeneratedGVK(&in.GeneratedGVK, &out.GeneratedGVK, s); err != nil {
		return err
	}
	return nil
}

// Convert_unversioned_ExpansionTemplateSpec_To_v1alpha1_ExpansionTemplateSpec is an autogenerated conversion function.
func Convert_unversioned_ExpansionTemplateSpec_To_v1alpha1_ExpansionTemplateSpec(in *unversioned.ExpansionTemplateSpec, out *ExpansionTemplateSpec, s conversion.Scope) error {
	return autoConvert_unversioned_ExpansionTemplateSpec_To_v1alpha1_ExpansionTemplateSpec(in, out, s)
}
