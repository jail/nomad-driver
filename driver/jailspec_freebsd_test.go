// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"testing"

	"github.com/jail/nomad-driver/jail"
)

// paramMap flattens a parameter list.  A parameter with no value maps to "".
func paramMap(t *testing.T, params []jail.Param) map[string]string {
	t.Helper()
	out := make(map[string]string, len(params))
	for _, p := range params {
		if _, dup := out[p.Name]; dup {
			t.Errorf("parameter %q appears twice", p.Name)
		}
		out[p.Name] = p.Value
	}
	return out
}

func TestJailParamsCommon(t *testing.T) {
	tc := defaultTaskConfig()
	st := &jailState{Name: "nomad-abc12345-web", Root: "/jails/web"}

	params, err := jailParams(tc, st, NetworkInherit, "web.example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := paramMap(t, params)

	for name, want := range map[string]string{
		"name":           "nomad-abc12345-web",
		"path":           "/jails/web",
		"host.hostname":  "web.example.com",
		"enforce_statfs": "2",
		"children.max":   "0",
		"devfs_ruleset":  "4",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}

	// The jail has to outlive the jail_set(2) call that created it; the
	// task is started afterwards.
	if _, ok := got["persist"]; !ok {
		t.Error("persist is not set, so the kernel would tear the jail down immediately")
	}
	// Not asked for, so not sent.
	if _, ok := got["securelevel"]; ok {
		t.Error("securelevel was sent even though the task did not ask for one")
	}
}

func TestJailParamsSecurelevel(t *testing.T) {
	tc := defaultTaskConfig()
	tc.Securelevel = 2
	st := &jailState{Name: "j", Root: "/jails/web"}

	params, err := jailParams(tc, st, NetworkInherit, "j")
	if err != nil {
		t.Fatal(err)
	}
	if got := paramMap(t, params)["securelevel"]; got != "2" {
		t.Errorf("securelevel = %q, want 2", got)
	}
}

func TestJailParamsNoDevfsRuleset(t *testing.T) {
	tc := defaultTaskConfig()
	tc.MountDevfs = false
	st := &jailState{Name: "j", Root: "/jails/web"}

	params, err := jailParams(tc, st, NetworkInherit, "j")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := paramMap(t, params)["devfs_ruleset"]; ok {
		t.Error("devfs_ruleset was set for a task with no devfs")
	}
}

func TestJailNetworkParams(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		mutate  func(*TaskConfig)
		want    map[string]string
		absent  []string
		wantErr bool
	}{
		{
			name: "inherit shares the host's addresses",
			mode: NetworkInherit,
			want: map[string]string{"ip4": "inherit", "ip6": "inherit"},
		},
		{
			name: "none leaves only loopback",
			mode: NetworkNone,
			want: map[string]string{"ip4": "disable", "ip6": "disable"},
		},
		{
			name:   "vnet asks the kernel for a stack of its own",
			mode:   NetworkVnet,
			want:   map[string]string{"vnet": "new"},
			absent: []string{"ip4", "ip6", "ip4.addr"},
		},
		{
			name: "alias passes bare addresses to the kernel",
			mode: NetworkAlias,
			mutate: func(tc *TaskConfig) {
				// The interface and prefix length describe a
				// host alias, and are not the kernel's
				// business.
				tc.IP4Addr = []string{"em0|10.0.0.5/24", "10.0.0.6"}
			},
			want:   map[string]string{"ip4.addr": "10.0.0.5,10.0.0.6", "ip6": "disable"},
			absent: []string{"ip4"},
		},
		{
			name: "alias with IPv6 only",
			mode: NetworkAlias,
			mutate: func(tc *TaskConfig) {
				tc.IP6Addr = []string{"em0|2001:db8::5/64"}
			},
			want: map[string]string{"ip6.addr": "2001:db8::5", "ip4": "disable"},
		},
		{
			name: "alias with an address that is not one",
			mode: NetworkAlias,
			mutate: func(tc *TaskConfig) {
				tc.IP4Addr = []string{"em0|nonsense"}
			},
			wantErr: true,
		},
		{
			name:    "unknown mode",
			mode:    "bridge",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mode == NetworkVnet && !jail.HasParam("vnet") {
				t.Skip("kernel has no VIMAGE support")
			}
			task := defaultTaskConfig()
			if tc.mutate != nil {
				tc.mutate(task)
			}
			st := &jailState{Name: "j", Root: "/jails/web"}

			params, err := jailNetworkParams(task, st, tc.mode)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("jailNetworkParams = %v, want an error", params)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := paramMap(t, params)
			for name, want := range tc.want {
				if got[name] != want {
					t.Errorf("%s = %q, want %q", name, got[name], want)
				}
			}
			for _, name := range tc.absent {
				if _, ok := got[name]; ok {
					t.Errorf("%s was set, want it absent", name)
				}
			}
		})
	}
}

func TestJailParamsAllowAndPassthrough(t *testing.T) {
	tc := defaultTaskConfig()
	tc.Allow = []string{"mount", "mount.zfs"}
	tc.JailParams = map[string]string{"osrelease": "14.2-RELEASE", "allow.mlock": "true"}
	st := &jailState{Name: "j", Root: "/jails/web"}

	params, err := jailParams(tc, st, NetworkInherit, "j")
	if err != nil {
		t.Fatal(err)
	}
	got := paramMap(t, params)

	for _, name := range []string{"allow.mount", "allow.mount.zfs", "allow.mlock"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s was not set", name)
		}
	}
	if got["osrelease"] != "14.2-RELEASE" {
		t.Errorf("osrelease = %q, want 14.2-RELEASE", got["osrelease"])
	}
}

// TestJailParamsAreAcceptedByTheKernel builds a real jail from the parameters
// the driver derives.
func TestJailParamsAreAcceptedByTheKernel(t *testing.T) {
	requireRoot(t)

	root := t.TempDir()
	tc := defaultTaskConfig()
	tc.Path = root
	tc.MountDevfs = false // no devfs in a temporary directory
	tc.Securelevel = 1
	st := &jailState{Name: "nomadjailspectest", Root: root}

	params, err := jailParams(tc, st, NetworkInherit, "spec.test")
	if err != nil {
		t.Fatal(err)
	}

	jid, err := jail.Set(jail.FlagCreate, params...)
	if err != nil {
		t.Fatalf("the kernel rejected the driver's parameters: %v", err)
	}
	t.Cleanup(func() { _ = jail.Remove(jid) })

	info, err := jail.Inspect(st.Name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname != "spec.test" {
		t.Errorf("hostname = %q, want spec.test", info.Hostname)
	}
}

func TestJailParamsVnetAcceptedByTheKernel(t *testing.T) {
	requireRoot(t)
	if !jail.HasParam("vnet") {
		t.Skip("kernel has no VIMAGE support")
	}

	root := t.TempDir()
	tc := defaultTaskConfig()
	tc.Path = root
	tc.MountDevfs = false
	tc.NetworkMode = NetworkVnet
	st := &jailState{Name: "nomadjailvnettest", Root: root}

	params, err := jailParams(tc, st, NetworkVnet, "vnet.test")
	if err != nil {
		t.Fatal(err)
	}
	jid, err := jail.Set(jail.FlagCreate, params...)
	if err != nil {
		t.Fatalf("the kernel rejected the driver's vnet parameters: %v", err)
	}
	t.Cleanup(func() { _ = jail.Remove(jid) })
}

func TestDevfsRuleset(t *testing.T) {
	tc := defaultTaskConfig()
	if got := devfsRuleset(tc, NetworkInherit); got != devfsRulesetJail {
		t.Errorf("ruleset = %d, want %d", got, devfsRulesetJail)
	}
	if got := devfsRuleset(tc, NetworkVnet); got != devfsRulesetJailVnet {
		t.Errorf("ruleset = %d, want %d for a vnet task", got, devfsRulesetJailVnet)
	}
	tc.DevfsRuleset = 42
	if got := devfsRuleset(tc, NetworkVnet); got != 42 {
		t.Errorf("ruleset = %d, want the task's own 42", got)
	}
}

// requireRoot skips a test that needs privilege.
func requireRoot(t *testing.T) {
	t.Helper()
	if geteuid() != 0 {
		t.Skip("test needs root")
	}
}

// TestRCTLRulesAreAllOrNothingPerTask checks what applyRCTL and StartTask's
// task event rely on: every derived rule is installed, or none is and the task
// is told so.
func TestRCTLRulesAreAllOrNothingPerTask(t *testing.T) {
	st := &jailState{Name: "nomad-abc12345-web"}
	rules := rctlRules(st, defaultTaskConfig(), nil)
	if len(rules) != 0 {
		t.Fatalf("a task with no resources should want no rules, got %v", rules)
	}
}
