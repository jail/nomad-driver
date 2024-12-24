// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package driver

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

// specNames returns the names an hclspec object declares at its top level.
func specNames(t *testing.T, spec *hclspec.Spec) []string {
	t.Helper()

	obj, ok := spec.Block.(*hclspec.Spec_Object)
	if !ok {
		t.Fatalf("spec is a %T, want an object", spec.Block)
	}
	names := make([]string, 0, len(obj.Object.Attributes))
	for name := range obj.Object.Attributes {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// codecNames returns the names the msgpack codec looks for when decoding into
// v, which is what Nomad sends.
func codecNames(t *testing.T, v any) []string {
	t.Helper()

	typ := reflect.TypeOf(v)
	names := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		tag, ok := typ.Field(i).Tag.Lookup("codec")
		if !ok {
			t.Errorf("%s.%s has no codec tag, so it can never be decoded",
				typ.Name(), typ.Field(i).Name)
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// TestSchemasMatchTheirStructs keeps each HCL schema and the struct it decodes
// into from drifting apart.
//
// They fail silently when they disagree.  A struct field with no schema entry
// is always its zero value, whatever the job says; a schema entry with no
// struct field is accepted from the job and dropped.
func TestSchemasMatchTheirStructs(t *testing.T) {
	tests := []struct {
		name string
		spec *hclspec.Spec
		into any
	}{
		{name: "plugin configuration", spec: configSpec, into: Config{}},
		{name: "task configuration", spec: taskConfigSpec, into: TaskConfig{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inSpec := specNames(t, tc.spec)
			inStruct := codecNames(t, tc.into)

			for _, name := range inSpec {
				if !slices.Contains(inStruct, name) {
					t.Errorf("%q is in the schema but has no field, so a job setting it is silently ignored", name)
				}
			}
			for _, name := range inStruct {
				if !slices.Contains(inSpec, name) {
					t.Errorf("%q is a field but is not in the schema, so it is always its zero value", name)
				}
			}
		})
	}
}

// TestDevfsRulesetsAreNeverZero guards against ruleset 0, the kernel default,
// which hides nothing.
func TestDevfsRulesetsAreNeverZero(t *testing.T) {
	if devfsRulesetJail == 0 || devfsRulesetJailVnet == 0 {
		t.Fatalf("a default devfs ruleset is 0, which hides nothing: jail=%d vnet=%d",
			devfsRulesetJail, devfsRulesetJailVnet)
	}
	if devfsRulesetJail == devfsRulesetJailVnet {
		t.Errorf("the vnet ruleset should differ from the plain one; both are %d", devfsRulesetJail)
	}
}
