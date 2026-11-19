// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package driver

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/nomad/plugins/base"
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

// attrTypes collects the type of every attribute in a schema, however deeply
// nested.
func attrTypes(spec *hclspec.Spec, name string, into map[string]string) {
	switch b := spec.Block.(type) {
	case *hclspec.Spec_Attr:
		into[name] = b.Attr.Type
	case *hclspec.Spec_Object:
		for child, s := range b.Object.Attributes {
			attrTypes(s, name+"."+child, into)
		}
	case *hclspec.Spec_Default:
		attrTypes(b.Default.Primary, name, into)
	case *hclspec.Spec_BlockValue:
		attrTypes(b.BlockValue.Nested, name, into)
	case *hclspec.Spec_BlockList:
		attrTypes(b.BlockList.Nested, name, into)
	case *hclspec.Spec_BlockSet:
		attrTypes(b.BlockSet.Nested, name, into)
	case *hclspec.Spec_BlockMap:
		attrTypes(b.BlockMap.Nested, name, into)
	}
}

// TestTaskSchemaHasNoBareMaps is the regression test for jail_params and a
// mount's options being declared map(string).  Nomad delivers an HCL object as
// a list of objects, so such a setting fails validation in the client for every
// job that sets it.
func TestTaskSchemaHasNoBareMaps(t *testing.T) {
	types := map[string]string{}
	attrTypes(taskConfigSpec, "config", types)
	if len(types) == 0 {
		t.Fatal("found no attributes in the task schema")
	}
	for name, typ := range types {
		if strings.HasPrefix(typ, "map(") {
			t.Errorf("%s is declared %s; a task setting that is a map has to be list(%s)", name, typ, typ)
		}
	}
	for _, name := range []string{"config.jail_params", "config.mount.options"} {
		if types[name] != "list(map(string))" {
			t.Errorf("%s is declared %q, want list(map(string))", name, types[name])
		}
	}
}

// TestMapListDecodes checks that the shape Nomad sends decodes, and merges.
func TestMapListDecodes(t *testing.T) {
	sent := map[string]any{
		"command": "/bin/sh",
		"jail_params": []map[string]string{
			{"allow.mlock": "true", "osrelease": "14.3-RELEASE"},
			{"osrelease": "15.0-RELEASE"},
		},
		"mount": []map[string]any{{
			"target":  "/tmp",
			"type":    "tmpfs",
			"options": []map[string]string{{"size": "64m"}},
		}},
	}
	var buf []byte
	if err := base.MsgPackEncode(&buf, sent); err != nil {
		t.Fatal(err)
	}
	var tc TaskConfig
	if err := base.MsgPackDecode(buf, &tc); err != nil {
		t.Fatalf("decoding what Nomad sends: %v", err)
	}

	params := tc.JailParams.merged()
	if params["allow.mlock"] != "true" || params["osrelease"] != "15.0-RELEASE" || len(params) != 2 {
		t.Errorf("jail_params = %v, want the entries merged with the later winning", params)
	}
	if len(tc.Mounts) != 1 || tc.Mounts[0].Options.merged()["size"] != "64m" {
		t.Errorf("mount = %+v, want its options decoded", tc.Mounts)
	}
	if got := (mapList)(nil).merged(); len(got) != 0 {
		t.Errorf("an unset map merged to %v", got)
	}
}
