// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/jail/nomad-driver/jail"
)

// newTestDriver returns a driver with enough filled in to run what needs no
// Nomad agent.
func newTestDriver(t *testing.T) *Driver {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Driver{
		config:  &Config{Enabled: true, DefaultNetworkMode: NetworkInherit},
		tasks:   newTaskStore(),
		records: newRecordStore(t.TempDir()),
		ctx:     ctx,
		logger:  hclog.NewNullLogger(),
	}
}

// testJail creates a persistent jail and removes it when the test ends.  The
// name carries the process ID, so that a run that died does not fail the next
// on the name.
func testJail(t *testing.T, label string, params ...jail.Param) (string, int) {
	t.Helper()

	name := fmt.Sprintf("%s%d", label, os.Getpid())
	params = append([]jail.Param{
		{Name: jail.ParamName, Value: name},
		{Name: jail.ParamPath, Value: t.TempDir()},
		{Name: jail.ParamPersist},
	}, params...)
	jid, err := jail.Set(jail.FlagCreate, params...)
	if err != nil {
		t.Fatalf("creating jail %s: %v", name, err)
	}
	t.Cleanup(func() { _ = removeJail(name) })
	return name, jid
}

func jailAlive(t *testing.T, name string) bool {
	t.Helper()

	info, err := jail.Inspect(name)
	switch {
	case errors.Is(err, jail.ErrNotFound):
		return false
	case err != nil:
		t.Fatalf("looking for jail %s: %v", name, err)
	}
	return !info.Dying
}

// TestTeardownDoesNotRemoveByJailID is the regression test for removing a jail
// by the ID in the task's state.
//
// After a reboot Nomad hands the driver the state it wrote before, and the ID
// in it belongs to whatever was started first this time.  The bystander stands
// for that jail.
func TestTeardownDoesNotRemoveByJailID(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)

	bystander, jid := testJail(t, "bystander")

	// The task's own jail is gone; the bystander has its old ID.
	st := &jailState{Name: "nomad-00000000-gone", JID: jid}
	if err := d.teardown(d.logger, st); err != nil {
		t.Errorf("teardown: %v", err)
	}

	if !jailAlive(t, bystander) {
		t.Fatalf("teardown removed %s, a jail that only shared an ID with the task's", bystander)
	}
}

// TestTeardownFindsTheJailByName is the other half: the jail is the task's
// whatever ID the state claims for it.
func TestTeardownFindsTheJailByName(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)

	name, jid := testJail(t, "nomad-teardown-")

	for _, stale := range []int{0, jid + 1000} {
		st := &jailState{Name: name, JID: stale}
		if err := d.teardown(d.logger, st); err != nil {
			t.Errorf("teardown with jail ID %d: %v", stale, err)
		}
		if jailAlive(t, name) {
			t.Fatalf("teardown with jail ID %d left %s running", stale, name)
		}
	}
}

func TestRemoveJailIsIdempotent(t *testing.T) {
	requireRoot(t)

	name, _ := testJail(t, "nomad-remove-")
	for i := range 3 {
		if err := removeJail(name); err != nil {
			t.Fatalf("removeJail, call %d: %v", i+1, err)
		}
	}
	if err := removeJail("nomad-00000000-never-existed"); err != nil {
		t.Errorf("removeJail of a jail that never existed: %v", err)
	}
	if err := removeJail(""); err != nil {
		t.Errorf("removeJail of no jail at all: %v", err)
	}
}

// requireEpair skips a test on a host that cannot make an epair(4), and returns
// the host leg of a new one, destroyed when the test ends.
func requireEpair(t *testing.T, d *Driver) string {
	t.Helper()

	out, err := run(d.ctx, d.logger, pathIfconfig, "epair", "create")
	if err != nil {
		t.Skipf("cannot create an epair: %v", err)
	}
	name := strings.TrimSpace(out)
	t.Cleanup(func() { _, _ = run(context.Background(), d.logger, pathIfconfig, name, "destroy") })
	return name
}

// TestTeardownDoesNotDestroyByInterfaceName is the same regression for the
// epair: "epair0a" in a task's state is, after a reboot, somebody else's.
func TestTeardownDoesNotDestroyByInterfaceName(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)

	bystander := requireEpair(t, d)

	st := &jailState{Name: "nomad-00000000-gone", Epair: bystander}
	if err := d.teardown(d.logger, st); err != nil {
		t.Errorf("teardown: %v", err)
	}

	if interfaceGone(d.ctx, d.logger, bystander) {
		t.Fatalf("teardown destroyed %s, an interface that only shared a name with the task's", bystander)
	}
}

// TestReclaimDestroysTheEpair checks that a vnet jail found on the system, with
// no state to say it had an epair, does not leave the pair behind.
func TestReclaimDestroysTheEpair(t *testing.T) {
	requireRoot(t)
	if !jail.HasParam("vnet") {
		t.Skip("kernel has no VIMAGE support")
	}
	d := newTestDriver(t)

	name, _ := testJail(t, "nomad-reclaim-", jail.Param{Name: "vnet", Value: "new"})

	created := requireEpair(t, d)
	hostSide, jailSide := epairHostName(name), strings.TrimSuffix(created, "a")+"b"
	if _, err := run(d.ctx, d.logger, pathIfconfig, created, "name", hostSide); err != nil {
		t.Fatalf("renaming %s: %v", created, err)
	}
	t.Cleanup(func() { _, _ = run(context.Background(), d.logger, pathIfconfig, hostSide, "destroy") })
	if _, err := run(d.ctx, d.logger, pathIfconfig, jailSide, "vnet", name); err != nil {
		t.Fatalf("moving %s into the jail: %v", jailSide, err)
	}

	info, err := jail.Inspect(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.teardown(d.logger, d.reclaimState(info)); err != nil {
		t.Errorf("teardown: %v", err)
	}

	for _, leg := range []string{hostSide, jailSide} {
		if !interfaceGone(d.ctx, d.logger, leg) {
			t.Errorf("%s outlived the jail it was made for", leg)
		}
	}
}
