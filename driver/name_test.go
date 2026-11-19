// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"strings"
	"testing"

	"github.com/hashicorp/nomad/plugins/drivers"
)

func TestJailName(t *testing.T) {
	tests := []struct {
		name  string
		alloc string
		task  string
		want  string
	}{
		{
			name:  "ordinary task",
			alloc: "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33",
			task:  "web",
			want:  "nomad-3a9c1b2e-web",
		},
		{
			name:  "a dot in the task name, which a jail name may not contain",
			alloc: "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33",
			task:  "web.v2",
			want:  "nomad-3a9c1b2e-web_v2",
		},
		{
			name:  "no allocation ID",
			alloc: "",
			task:  "web",
			want:  "nomad-noalloc-web",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := jailName(&drivers.TaskConfig{AllocID: tc.alloc, Name: tc.task})
			if got != tc.want {
				t.Errorf("jailName = %q, want %q", got, tc.want)
			}
			if !isDriverJail(got) {
				t.Errorf("%q is not recognised as one of the driver's jails", got)
			}
		})
	}
}

// TestJailNameDependsOnlyOnTheTask checks that the name is derived from the
// allocation ID and the task name alone.  A restarted driver finds a jail by
// deriving its name again, in another process, so anything else folded in would
// leave jails that nothing could match.
func TestJailNameDependsOnlyOnTheTask(t *testing.T) {
	// Two equal values rather than one value twice.
	first := &drivers.TaskConfig{AllocID: "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33", Name: "web"}
	second := &drivers.TaskConfig{AllocID: "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33", Name: "web"}

	if a, b := jailName(first), jailName(second); a != b {
		t.Errorf("equal tasks produced different jail names: %q and %q", a, b)
	}

	// Everything Nomad fills in that is not the allocation or the task.
	varied := &drivers.TaskConfig{
		AllocID:       "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33",
		Name:          "web",
		ID:            "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33/web/6f0b3a1c",
		JobName:       "some-job",
		TaskGroupName: "some-group",
		Namespace:     "some-namespace",
		NodeName:      "some-node",
		AllocDir:      "/var/nomad/alloc/3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33",
		Env:           map[string]string{"FOO": "bar"},
	}
	if a, b := jailName(first), jailName(varied); a != b {
		t.Errorf("the jail name changed with fields it should ignore: %q and %q", a, b)
	}
}

func TestJailNameDistinguishesTasksInOneAlloc(t *testing.T) {
	alloc := "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33"
	a := jailName(&drivers.TaskConfig{AllocID: alloc, Name: "web"})
	b := jailName(&drivers.TaskConfig{AllocID: alloc, Name: "sidecar"})
	if a == b {
		t.Errorf("two tasks in one allocation share the jail name %q", a)
	}
}

func TestSanitiseJailName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"web", "web"},
		{"web.v2", "web_v2"},
		{"web/v2", "web_v2"},
		{"", "task"},
		{"../etc", "___etc"},
		{"a-b_c9", "a-b_c9"},
	}
	for _, tc := range tests {
		if got := sanitiseJailName(tc.in); got != tc.want {
			t.Errorf("sanitiseJailName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	long := sanitiseJailName(strings.Repeat("x", 200))
	if len(long) > maxTaskNamePart {
		t.Errorf("sanitiseJailName did not bound the name: got %d characters", len(long))
	}
}

func TestIsDriverJail(t *testing.T) {
	if isDriverJail("mail") || isDriverJail("") {
		t.Error("a hand-made jail was taken for one of the driver's")
	}
	if !isDriverJail("nomad-abc12345-web") {
		t.Error("one of the driver's own jails was not recognised")
	}
}

func TestEpairHostName(t *testing.T) {
	name := epairHostName("nomad-3a9c1b2e-web")

	// IFNAMSIZ is 16, with the terminating NUL.
	if len(name) != 15 {
		t.Errorf("epairHostName = %q, %d characters; want 15", name, len(name))
	}
	if !validInterfaceName(name) {
		t.Errorf("epairHostName = %q, which is not a valid interface name", name)
	}
	if !strings.HasPrefix(name, epairNamePrefix) {
		t.Errorf("epairHostName = %q, want it to start with %q", name, epairNamePrefix)
	}

	// A driver that has lost its state finds the interface by deriving the
	// name again.
	if again := epairHostName("nomad-3a9c1b2e-web"); again != name {
		t.Errorf("epairHostName is not stable: %q then %q", name, again)
	}
	for _, other := range []string{"nomad-3a9c1b2e-web2", "nomad-3a9c1b2f-web", "nomad-3a9c1b2e-we"} {
		if epairHostName(other) == name {
			t.Errorf("jails %q and %q share the epair name %q", other, "nomad-3a9c1b2e-web", name)
		}
	}
}

// TestEpairHostNameIsNotAnEpairUnit keeps the derived name out of the namespace
// the kernel allocates from, where it could name somebody else's interface.
func TestEpairHostNameIsNotAnEpairUnit(t *testing.T) {
	for _, jail := range []string{"", "nomad-a", "nomad-3a9c1b2e-web"} {
		if name := epairHostName(jail); strings.HasPrefix(name, "epair") {
			t.Errorf("epairHostName(%q) = %q, inside the kernel's own namespace", jail, name)
		}
	}
}
