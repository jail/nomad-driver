// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/jail/nomad-driver/jail"
)

func TestRecordRoundTrip(t *testing.T) {
	r := newRecordStore(filepath.Join(t.TempDir(), "records"))
	if r.bootID == "" {
		t.Skip("this kernel has no kern.boot_id")
	}

	want := &jailState{
		Name:     "nomad-3a9c1b2e-web",
		AllocDir: "/var/nomad/alloc/3a9c1b2e/alloc",
		JID:      7,
		Root:     "/jails/web",
		Mounts:   []string{"/jails/web/dev", "/jails/web/data"},
		Aliases:  []string{"em0|10.0.0.5/24"},
	}
	if got := r.load(want.Name); got != nil {
		t.Fatalf("a record before any was saved: %+v", got)
	}
	if err := r.save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := r.load(want.Name); !reflect.DeepEqual(got, want) {
		t.Errorf("load = %+v, want %+v", got, want)
	}
	if got := r.names(); !slices.Equal(got, []string{want.Name}) {
		t.Errorf("names = %q, want the one jail", got)
	}

	// A later save replaces the record.
	want.Mounts = nil
	if err := r.save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := r.load(want.Name); !reflect.DeepEqual(got, want) {
		t.Errorf("load after a second save = %+v, want %+v", got, want)
	}

	r.remove(want.Name)
	if got := r.load(want.Name); got != nil {
		t.Errorf("a record after it was removed: %+v", got)
	}
}

// TestRecordFromAnotherBootIsNotBelieved checks what keeps the driver from
// acting on names that a reboot has given to something else.
func TestRecordFromAnotherBootIsNotBelieved(t *testing.T) {
	dir := t.TempDir()
	before := &recordStore{dir: dir, bootID: "before"}
	after := &recordStore{dir: dir, bootID: "after"}
	unknown := &recordStore{dir: dir}

	st := &jailState{Name: "nomad-3a9c1b2e-web", Mounts: []string{"/jails/web/data"}}
	if err := before.save(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := after.load(st.Name); got != nil {
		t.Errorf("a record from another boot was believed: %+v", got)
	}
	if got := before.load(st.Name); got != nil {
		t.Errorf("a record that was not believed was kept: %+v", got)
	}

	// Nor is anything believed where the kernel cannot say which boot
	// this is.
	if err := unknown.save(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := unknown.load(st.Name); got != nil {
		t.Errorf("a record was believed with no boot ID to hold it to: %+v", got)
	}
}

func TestRecordStaysInItsDirectory(t *testing.T) {
	outside := t.TempDir()
	r := &recordStore{dir: filepath.Join(outside, "records"), bootID: "boot"}

	for _, name := range []string{"", ".", "..", "../nomad-x", "a/b", ".hidden"} {
		if err := r.save(&jailState{Name: name}); err == nil {
			t.Errorf("save accepted the name %q", name)
		}
		if got := r.load(name); got != nil {
			t.Errorf("load(%q) = %+v", name, got)
		}
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("something was written outside the record directory: %v", entries)
	}
}

// jobMount null-mounts a directory at root/data, as a job's mount block would,
// and returns the mount point.  It is unmounted when the test ends.
func jobMount(t *testing.T, root string) string {
	t.Helper()

	target := filepath.Join(root, "data")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := jail.MountNullfs(t.TempDir(), target, 0); err != nil {
		t.Fatalf("mounting on %s: %v", target, err)
	}
	t.Cleanup(func() { _ = jail.UnmountAll(target, jail.MountForce) })
	return target
}

func mountedAt(t *testing.T, path string) bool {
	t.Helper()

	mounts, err := jail.MountsUnder(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(mounts) > 0
}

// TestReapGoesByTheRecord is the regression test for a reaped jail leaving
// behind what a job had mounted under a root it named.  Nothing about the jail
// says the mount is the driver's; the record does.
func TestReapGoesByTheRecord(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)
	if d.records.bootID == "" {
		t.Skip("this kernel has no kern.boot_id")
	}

	// With no /alloc mounted, the jail is an orphan.
	name, _ := testJail(t, "nomad-record-")
	info, err := jail.Inspect(name)
	if err != nil {
		t.Fatal(err)
	}
	mount := jobMount(t, info.Path)
	if err := d.records.save(&jailState{
		Name:     name,
		AllocDir: filepath.Join(t.TempDir(), "gone"),
		Root:     info.Path,
		Mounts:   []string{mount},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	d.reapOrphans()

	if jailAlive(t, name) {
		t.Errorf("jail %s was not reaped", name)
	}
	if mountedAt(t, mount) {
		t.Errorf("%s outlived the jail it was mounted for", mount)
	}
	if got := d.records.load(name); got != nil {
		t.Errorf("the record outlived what it describes: %+v", got)
	}
}

// TestReapFinishesWhatWasCutShort checks the records of jails that are gone: a
// start or a teardown that did not get to the end.  What is left goes once the
// allocation has, and not before.
func TestReapFinishesWhatWasCutShort(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)
	if d.records.bootID == "" {
		t.Skip("this kernel has no kern.boot_id")
	}

	name := fmt.Sprintf("nomad-cutshort-%d", os.Getpid())
	root, allocDir := t.TempDir(), t.TempDir()
	mount := jobMount(t, root)
	if err := d.records.save(&jailState{
		Name:     name,
		AllocDir: allocDir,
		Root:     root,
		Mounts:   []string{mount},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	d.reapOrphans()
	if !mountedAt(t, mount) || d.records.load(name) == nil {
		t.Fatal("reaped what belongs to an allocation Nomad still has")
	}

	if err := os.RemoveAll(allocDir); err != nil {
		t.Fatal(err)
	}
	d.reapOrphans()
	if mountedAt(t, mount) {
		t.Errorf("%s was left, with its allocation gone", mount)
	}
	if got := d.records.load(name); got != nil {
		t.Errorf("the record outlived what it describes: %+v", got)
	}
}

// TestRemainsLeaveAnotherJailsRootAlone checks that the record of a jail that
// is gone is not acted on where another jail has since been given its root.
func TestRemainsLeaveAnotherJailsRootAlone(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)
	if d.records.bootID == "" {
		t.Skip("this kernel has no kern.boot_id")
	}

	successor, _ := testJail(t, "nomad-successor-")
	info, err := jail.Inspect(successor)
	if err != nil {
		t.Fatal(err)
	}
	mount := jobMount(t, info.Path)

	gone := fmt.Sprintf("nomad-gone-%d", os.Getpid())
	if err := d.records.save(&jailState{Name: gone, Root: info.Path, Mounts: []string{mount}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	st := d.remains(d.logger, gone)
	if st == nil {
		t.Fatal("no record of the jail that is gone")
	}
	if err := d.teardown(d.logger, st); err != nil {
		t.Errorf("teardown: %v", err)
	}
	if !mountedAt(t, mount) {
		t.Errorf("%s was unmounted from under %s on the word of a jail that is gone", mount, successor)
	}
}

// TestTeardownRecordsWhatIsLeft checks that a teardown that could not finish
// leaves a record of what it could not undo, and of nothing else.
func TestTeardownRecordsWhatIsLeft(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)
	if d.records.bootID == "" {
		t.Skip("this kernel has no kern.boot_id")
	}

	root := t.TempDir()
	mount := jobMount(t, root)
	stuck := "nosuchif0|192.0.2.1/32"
	st := &jailState{
		Name:    fmt.Sprintf("nomad-left-%d", os.Getpid()),
		Root:    root,
		Mounts:  []string{mount},
		Aliases: []string{stuck},
	}
	if err := d.teardown(d.logger, st); err == nil {
		t.Fatal("teardown removed an alias from an interface that does not exist")
	}
	if mountedAt(t, mount) {
		t.Errorf("%s was left mounted", mount)
	}

	left := d.records.load(st.Name)
	if left == nil {
		t.Fatal("nothing records what the teardown left")
	}
	if !slices.Equal(left.Aliases, []string{stuck}) || len(left.Mounts) != 0 {
		t.Errorf("the record says %q and %q are left, want the alias alone", left.Aliases, left.Mounts)
	}

	left.Aliases = nil
	if err := d.teardown(d.logger, left); err != nil {
		t.Errorf("teardown: %v", err)
	}
	if got := d.records.load(st.Name); got != nil {
		t.Errorf("the record outlived what it describes: %+v", got)
	}
}
