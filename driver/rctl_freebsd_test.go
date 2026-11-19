// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/drivers"
)

func resources(memMB, memMaxMB int64, cores ...uint16) *drivers.Resources {
	return &drivers.Resources{
		NomadResources: &structs.AllocatedTaskResources{
			Memory: structs.AllocatedMemoryResources{MemoryMB: memMB, MemoryMaxMB: memMaxMB},
			Cpu:    structs.AllocatedCpuResources{ReservedCores: cores},
		},
	}
}

func TestRCTLRules(t *testing.T) {
	st := &jailState{Name: "nomad-abc12345-web"}

	tests := []struct {
		name string
		res  *drivers.Resources
		tc   func(*TaskConfig)
		want []string
	}{
		{
			name: "memory reservation becomes the limit",
			res:  resources(256, 0),
			want: []string{"jail:nomad-abc12345-web:memoryuse:deny=256M"},
		},
		{
			name: "an oversubscription ceiling is the limit, being what the task may reach",
			res:  resources(256, 512),
			want: []string{"jail:nomad-abc12345-web:memoryuse:deny=512M"},
		},
		{
			name: "no memory, no rule",
			res:  resources(0, 0),
			want: nil,
		},
		{
			name: "no resources at all",
			res:  nil,
			want: nil,
		},
		{
			name: "a rule the job gave is qualified with the jail",
			res:  resources(0, 0),
			tc:   func(tc *TaskConfig) { tc.ExtraRCTL = []string{"pcpu:deny=50", " "} },
			want: []string{"jail:nomad-abc12345-web:pcpu:deny=50"},
		},
		{
			name: "a task that turns its limits off keeps the rules it gave",
			res:  resources(256, 0),
			tc: func(tc *TaskConfig) {
				tc.ResourceLimits = false
				tc.ExtraRCTL = []string{"maxproc:deny=50"}
			},
			want: []string{"jail:nomad-abc12345-web:maxproc:deny=50"},
		},
		{
			name: "a fully spelled out rule is passed through",
			res:  resources(0, 0),
			tc:   func(tc *TaskConfig) { tc.ExtraRCTL = []string{"jail:other:pcpu:deny=50"} },
			want: []string{"jail:other:pcpu:deny=50"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := defaultTaskConfig()
			if tt.tc != nil {
				tt.tc(tc)
			}
			got := rctlRules(st, tc, tt.res)
			if !slices.Equal(got, tt.want) {
				t.Errorf("rctlRules = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRCTLRulesDoNotMentionCPUShares records a deliberate omission; see
// rctlRules.
func TestRCTLRulesDoNotMentionCPUShares(t *testing.T) {
	st := &jailState{Name: "j"}
	res := resources(0, 0)
	res.NomadResources.Cpu.CpuShares = 2000

	if got := rctlRules(st, defaultTaskConfig(), res); len(got) != 0 {
		t.Errorf("rctlRules = %v, want no rules for a CPU share", got)
	}
}

// TestRCTLAgainstTheKernel installs a task's rules on a real jail and removes
// them.  It needs kern.racct.enable, which is a loader tunable.
func TestRCTLAgainstTheKernel(t *testing.T) {
	requireRoot(t)
	if !racctEnabled() {
		t.Skip("kern.racct.enable is off")
	}

	d := newTestDriver(t)
	name, _ := testJail(t, "rctl")
	st := &jailState{Name: name}
	installed := func() string {
		t.Helper()
		out, err := run(d.ctx, d.logger, pathRCTL, "jail:"+name)
		if err != nil {
			t.Fatalf("listing rules: %v", err)
		}
		return out
	}

	tc := defaultTaskConfig()
	tc.ExtraRCTL = []string{"maxproc:deny=50"}
	added, err := applyRCTL(d.ctx, d.logger, rctlRules(st, tc, resources(64, 0)), true)
	if err != nil {
		t.Fatalf("applyRCTL: %v", err)
	}
	if len(added) != 2 {
		t.Errorf("applyRCTL added %q, want two rules", added)
	}
	got := installed()
	for _, want := range []string{
		"jail:" + name + ":memoryuse:deny=67108864",
		"jail:" + name + ":maxproc:deny=50",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rule %s is not installed; the jail has:\n%s", want, got)
		}
	}

	if err := removeRCTL(d.ctx, d.logger, st); err != nil {
		t.Fatalf("removeRCTL: %v", err)
	}
	if got := installed(); got != "" {
		t.Errorf("rules left after removeRCTL:\n%s", got)
	}
	// Teardown may run twice.
	if err := removeRCTL(d.ctx, d.logger, st); err != nil {
		t.Errorf("removeRCTL with nothing to remove: %v", err)
	}

	// A rule the kernel refuses fails the task.  What went in before it is
	// reported, and goes with the jail's other rules.
	tc.ExtraRCTL = []string{"nosuchresource:deny=1"}
	added, err = applyRCTL(d.ctx, d.logger, rctlRules(st, tc, resources(64, 0)), true)
	if err == nil {
		t.Error("applyRCTL accepted a resource the kernel does not have")
	}
	if len(added) != 1 {
		t.Errorf("applyRCTL reported %q as added, want the memory rule alone", added)
	}
	if err := removeRCTL(d.ctx, d.logger, st); err != nil {
		t.Fatalf("removeRCTL: %v", err)
	}
	if got := installed(); got != "" {
		t.Errorf("rules left after a failed applyRCTL was undone:\n%s", got)
	}
}
