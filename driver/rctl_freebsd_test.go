// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"slices"
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
