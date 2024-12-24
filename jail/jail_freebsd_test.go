// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// requireRoot skips a test that needs privilege.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test needs root")
	}
}

func TestLookupParamTypes(t *testing.T) {
	tests := []struct {
		name     string
		ctltype  uint32
		flags    paramFlags
		array    bool
		minWidth int
	}{
		{name: "jid", ctltype: ctltypeInt},
		{name: "name", ctltype: ctltypeString, minWidth: 2},
		{name: "path", ctltype: ctltypeString, minWidth: 2},
		{name: "host.hostname", ctltype: ctltypeString, minWidth: 2},
		{name: "persist", ctltype: ctltypeInt, flags: flagBool},
		{name: "nopersist", ctltype: ctltypeInt, flags: flagNoBool},
		{name: "allow.mount", ctltype: ctltypeInt, flags: flagBool},
		{name: "allow.nomount", ctltype: ctltypeInt, flags: flagNoBool},
		{name: "securelevel", ctltype: ctltypeInt},
		{name: "enforce_statfs", ctltype: ctltypeInt},
		{name: "children.max", ctltype: ctltypeInt},
		{name: "devfs_ruleset", ctltype: ctltypeInt},
		// CTLTYPE_NODE indirection: the type of these nodes lives in an
		// adjacent, empty-named child.
		{name: "host", ctltype: ctltypeInt, flags: flagJailSys},
		{name: "ip4", ctltype: ctltypeInt, flags: flagJailSys},
		{name: "ip6", ctltype: ctltypeInt, flags: flagJailSys},
		// Array of struct in_addr.
		{name: "ip4.addr", ctltype: ctltypeStruct, array: true, minWidth: 4},
		{name: "ip6.addr", ctltype: ctltypeStruct, array: true, minWidth: 16},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := lookupParam(tc.name)
			if err != nil {
				t.Fatalf("lookupParam(%q): %v", tc.name, err)
			}
			if got := p.ctltype(); got != tc.ctltype {
				t.Errorf("ctltype = %d, want %d (format %q)", got, tc.ctltype, p.format)
			}
			if p.flags != tc.flags {
				t.Errorf("flags = %#b, want %#b (format %q)", p.flags, tc.flags, p.format)
			}
			if p.array != tc.array {
				t.Errorf("array = %v, want %v (format %q)", p.array, tc.array, p.format)
			}
			if p.width < tc.minWidth {
				t.Errorf("width = %d, want at least %d", p.width, tc.minWidth)
			}
		})
	}
}

func TestLookupParamVnet(t *testing.T) {
	if !HasParam("vnet") {
		t.Skip("kernel has no VIMAGE support")
	}
	p, err := lookupParam("vnet")
	if err != nil {
		t.Fatal(err)
	}
	if p.flags&flagJailSys == 0 {
		t.Errorf("vnet should be an E,jailsys parameter, got format %q", p.format)
	}
}

func TestLookupParamUnknown(t *testing.T) {
	if _, err := lookupParam("no.such.parameter"); !errors.Is(err, errUnknownParam) {
		t.Errorf("err = %v, want errUnknownParam", err)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	tests := []struct {
		param    string
		value    string
		wantName string
		wantText string // value as decode() renders it, "" to skip
	}{
		{param: "persist", value: "", wantName: "persist"},
		{param: "persist", value: "true", wantName: "persist"},
		{param: "persist", value: "false", wantName: "nopersist"},
		{param: "nopersist", value: "false", wantName: "persist"},
		{param: "allow.mount", value: "no", wantName: "allow.nomount"},
		{param: "host.hostname", value: "db-1.example.com", wantName: "host.hostname", wantText: "db-1.example.com"},
		{param: "securelevel", value: "2", wantName: "securelevel", wantText: "2"},
		{param: "ip4", value: "inherit", wantName: "ip4", wantText: "inherit"},
		{param: "ip4.addr", value: "10.0.0.1,10.0.0.2", wantName: "ip4.addr", wantText: "10.0.0.1,10.0.0.2"},
		{param: "ip6.addr", value: "2001:db8::1", wantName: "ip6.addr", wantText: "2001:db8::1"},
	}

	for _, tc := range tests {
		t.Run(tc.param+"="+tc.value, func(t *testing.T) {
			p, err := lookupParam(tc.param)
			if err != nil {
				t.Fatal(err)
			}
			name, raw, err := p.encode(tc.param, tc.value)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if tc.wantText == "" {
				if raw != nil {
					t.Errorf("value = %v, want nil for a boolean", raw)
				}
				return
			}
			got, err := p.decode(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != tc.wantText {
				t.Errorf("round trip = %q, want %q", got, tc.wantText)
			}
		})
	}
}

func TestEncodeRejectsBadValues(t *testing.T) {
	tests := []struct{ param, value string }{
		{"securelevel", "high"},
		{"ip4", "maybe"},
		{"ip4.addr", "2001:db8::1"},
		{"ip6.addr", "10.0.0.1"},
		{"persist", "perhaps"},
		{"host.hostname", strings.Repeat("x", 4096)},
	}
	for _, tc := range tests {
		t.Run(tc.param+"="+tc.value, func(t *testing.T) {
			p, err := lookupParam(tc.param)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := p.encode(tc.param, tc.value); err == nil {
				t.Errorf("encode(%q, %q) succeeded, want an error", tc.param, tc.value)
			}
		})
	}
}

func TestListFindsPrison0(t *testing.T) {
	if _, err := List(); err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestFindIDNotFound(t *testing.T) {
	_, err := FindID("nomad-test-definitely-no-such-jail")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestJailLifecycle(t *testing.T) {
	requireRoot(t)

	root := t.TempDir()
	name := "nomadjailtest"

	jid, err := Set(FlagCreate,
		Param{Name: ParamName, Value: name},
		Param{Name: ParamPath, Value: root},
		Param{Name: "host.hostname", Value: "lifecycle.test"},
		Param{Name: "enforce_statfs", Value: "2"},
		Param{Name: ParamPersist},
	)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = Remove(jid) })

	if got, err := FindID(name); err != nil || got != jid {
		t.Errorf("FindID = %d, %v; want %d, nil", got, err, jid)
	}

	info, err := Inspect(name)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.JID != jid || info.Name != name || info.Path != root {
		t.Errorf("Inspect = %+v, want jid %d name %q path %q", info, jid, name, root)
	}
	if info.Hostname != "lifecycle.test" {
		t.Errorf("hostname = %q, want %q", info.Hostname, "lifecycle.test")
	}

	var found bool
	list, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, i := range list {
		if i.JID == jid {
			found = true
		}
	}
	if !found {
		t.Errorf("List did not include jid %d", jid)
	}

	// An update must address the existing jail, not make another.
	if got, err := Set(FlagUpdate,
		Param{Name: ParamName, Value: name},
		Param{Name: "host.hostname", Value: "updated.test"},
	); err != nil || got != jid {
		t.Fatalf("Set update = %d, %v; want %d, nil", got, err, jid)
	}
	if info, err := Inspect(name); err != nil || info.Hostname != "updated.test" {
		t.Errorf("after update: %+v, %v", info, err)
	}

	if err := Remove(jid); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := FindID(name); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Remove, FindID err = %v, want ErrNotFound", err)
	}
}

func TestSetReportsKernelErrmsg(t *testing.T) {
	requireRoot(t)

	// The kernel rejects a jail with no path, and says why.
	_, err := Set(FlagCreate, Param{Name: ParamName, Value: "nomadjailbadtest"})
	if err == nil {
		t.Fatal("Set with no path succeeded")
	}
	var jerr *Error
	if !errors.As(err, &jerr) {
		t.Fatalf("err = %v (%T), want *jail.Error", err, err)
	}
	if jerr.Msg == "" {
		t.Errorf("no kernel errmsg in %v", err)
	}
}

func TestSetRejectsUnknownParam(t *testing.T) {
	_, err := Set(FlagCreate, Param{Name: "definitely.not.a.param", Value: "1"})
	if !errors.Is(err, errUnknownParam) {
		t.Errorf("err = %v, want errUnknownParam", err)
	}
}
