// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/allocdir"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/jail/nomad-driver/jail"
)

func TestResolveUnder(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/local"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A symlink in the image that points out of it must not be followed.
	if err := os.Symlink("/etc", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	// One that points within it is fine.
	if err := os.Symlink("usr/local", filepath.Join(root, "inside")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		inner   string
		want    string
		wantErr string
	}{
		{name: "existing directory", inner: "/usr/local", want: filepath.Join(root, "usr/local")},
		{name: "path that does not exist yet", inner: "/alloc", want: filepath.Join(root, "alloc")},
		{name: "deep path that does not exist yet", inner: "/a/b/c", want: filepath.Join(root, "a/b/c")},
		{name: "symlink within the image", inner: "/inside", want: filepath.Join(root, "usr/local")},
		{name: "symlink out of the image", inner: "/escape", wantErr: "outside the jail root"},
		{name: "path under a symlink out of the image", inner: "/escape/passwd", wantErr: "outside the jail root"},
		{name: "dot dot", inner: "/../../etc", want: filepath.Join(root, "etc")},
		{name: "relative", inner: "alloc", wantErr: "absolute path"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveUnder(root, tc.inner)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveUnder(%q) = %q, %v; want an error containing %q",
						tc.inner, got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveUnder(%q): %v", tc.inner, err)
			}
			// The temporary directory may itself be reached through
			// a symlink.
			wantResolved, _ := filepath.EvalSymlinks(tc.want)
			if wantResolved == "" {
				wantResolved = tc.want
			}
			if got != tc.want && got != wantResolved {
				t.Errorf("resolveUnder(%q) = %q, want %q", tc.inner, got, tc.want)
			}
		})
	}
}

func TestTaskMountsOrderAndFlags(t *testing.T) {
	cfg := &drivers.TaskConfig{
		AllocID:  "3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33",
		Name:     "web",
		AllocDir: "/var/nomad/alloc/3a9c1b2e-7f44-4c21-9b88-0d5e6a1f2c33",
		Mounts: []*drivers.MountConfig{
			{HostPath: "/srv/data", TaskPath: "/data", Readonly: true},
		},
	}
	tc := defaultTaskConfig()
	tc.MountProcfs = true
	tc.Mounts = []MountConfig{{Source: "/usr/ports", Target: "/usr/ports", Type: "nullfs", Readonly: true}}

	mounts := taskMounts(cfg, tc, &Config{}, NetworkInherit)

	var targets []string
	for _, m := range mounts {
		targets = append(targets, m.Target)
	}

	// devfs and the task's own directories come before anything a job asked
	// for, so that a job cannot shadow them.
	wantPrefix := []string{
		taskDevDirPath,
		allocdir.SharedAllocContainerPath,
		allocdir.TaskLocalContainerPath,
		allocdir.TaskSecretsContainerPath,
	}
	for i, want := range wantPrefix {
		if i >= len(targets) || targets[i] != want {
			t.Fatalf("mount order = %v, want it to start with %v", targets, wantPrefix)
		}
	}
	if targets[len(targets)-1] != "/data" {
		t.Errorf("Nomad's own mounts should come last, order was %v", targets)
	}

	byTarget := map[string]mountSpec{}
	for _, m := range mounts {
		byTarget[m.Target] = m
	}

	// Secrets hold credentials, never anything to run.
	secrets := byTarget[allocdir.TaskSecretsContainerPath]
	if secrets.Flags&(jailMountNoSUID|jailMountNoExec) != jailMountNoSUID|jailMountNoExec {
		t.Errorf("/secrets flags = %#x, want nosuid and noexec", secrets.Flags)
	}
	if got := byTarget[taskDevDirPath].Options["ruleset"]; got != "4" {
		t.Errorf("devfs ruleset = %q, want 4 for a non-vnet task", got)
	}
	if byTarget["/data"].Flags&jailMountReadOnly == 0 {
		t.Error("a read-only Nomad mount was not mounted read-only")
	}
	if byTarget["/usr/ports"].Flags&jailMountReadOnly == 0 {
		t.Error("a read-only config mount was not mounted read-only")
	}
}

func TestTaskMountsDevfsRulesetForVnet(t *testing.T) {
	cfg := &drivers.TaskConfig{Name: "web", AllocDir: "/var/nomad/alloc/x"}
	tc := defaultTaskConfig()

	mounts := taskMounts(cfg, tc, &Config{}, NetworkVnet)
	if got := mounts[0].Options["ruleset"]; got != "5" {
		t.Errorf("devfs ruleset = %q, want 5 (devfsrules_jail_vnet) for a vnet task", got)
	}

	tc.DevfsRuleset = 11
	mounts = taskMounts(cfg, tc, &Config{}, NetworkVnet)
	if got := mounts[0].Options["ruleset"]; got != "11" {
		t.Errorf("devfs ruleset = %q, want the task's own 11", got)
	}
}

func TestWriteResolvConf(t *testing.T) {
	root := t.TempDir()

	if err := writeResolvConf(root, nil); err != nil {
		t.Errorf("no DNS configuration should be a no-op, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/resolv.conf")); !os.IsNotExist(err) {
		t.Error("writeResolvConf wrote a file for an empty DNS configuration")
	}

	err := writeResolvConf(root, &drivers.DNSConfig{
		Servers:  []string{"10.0.0.1", "10.0.0.2"},
		Searches: []string{"example.com", "svc.example.com"},
		Options:  []string{"ndots:2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "etc/resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"search example.com svc.example.com\n",
		"nameserver 10.0.0.1\n",
		"nameserver 10.0.0.2\n",
		"options ndots:2\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("resolv.conf is missing %q; it is:\n%s", want, got)
		}
	}
}

func TestDriverMountPoints(t *testing.T) {
	got := driverMountPoints("/jails/web")
	for _, want := range []string{"/jails/web/dev", "/jails/web/alloc", "/jails/web/local", "/jails/web/secrets"} {
		var found bool
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("driverMountPoints is missing %q, got %v", want, got)
		}
	}

	// /dev/fd is listed after /dev: teardown goes in reverse, and a child
	// must go before its parent.
	var dev, devfd = -1, -1
	for i, g := range got {
		switch g {
		case "/jails/web/dev":
			dev = i
		case "/jails/web/dev/fd":
			devfd = i
		}
	}
	if dev < 0 || devfd < 0 || devfd < dev {
		t.Errorf("/dev/fd must come after /dev so it is unmounted first; got %v", got)
	}
}

func TestUnmountAllTargets(t *testing.T) {
	// A root the job named: only what the driver mounted goes, or a thin
	// jail's own mounts would go with the task.
	named := &jailState{Root: "/jails/web", Mounts: []string{"/jails/web/dev", "/jails/web/local"}}
	if ownsRootMount(named) {
		t.Error("a job-named root should not be treated as the driver's own mount")
	}

	// A root the driver mounted: the whole tree is the task's.
	owned := &jailState{
		Root:   "/var/nomad/alloc/x/web/jail",
		Mounts: []string{"/var/nomad/alloc/x/web/jail", "/var/nomad/alloc/x/web/jail/dev"},
	}
	if !ownsRootMount(owned) {
		t.Error("a root the driver null-mounted should be treated as its own")
	}
}

func TestResolveUnderWithASymlinkedRoot(t *testing.T) {
	// prepareRootfs resolves the root, so resolveUnder is only ever given a
	// real path.  The kernel reports real paths, and a root reached through
	// a symlink would break both target checking and teardown.
	real := t.TempDir()
	realResolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(realResolved, link); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(realResolved, "usr"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveUnder(realResolved, "/usr")
	if err != nil {
		t.Fatalf("resolveUnder with a real root: %v", err)
	}
	if got != filepath.Join(realResolved, "usr") {
		t.Errorf("resolveUnder = %q, want %q", got, filepath.Join(realResolved, "usr"))
	}
}

func TestCheckRootNotInUse(t *testing.T) {
	// With nothing mounted, a root is free.
	root := t.TempDir()
	if err := checkRootNotInUse(root); err != nil {
		t.Errorf("an unused root was refused: %v", err)
	}
}

func TestCheckRootNotInUseRefusesASharedRoot(t *testing.T) {
	requireRoot(t)

	root := t.TempDir()
	source := t.TempDir()
	target := filepath.Join(root, "local")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}

	// Stand in for another allocation that has its /local here.
	if err := jail.MountNullfs(source, target, 0); err != nil {
		t.Fatalf("setting up the test mount: %v", err)
	}
	t.Cleanup(func() { _ = jail.Unmount(target, jail.MountForce) })

	err := checkRootNotInUse(root)
	if err == nil {
		t.Fatal("a root already in use by another allocation was accepted")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error does not explain the conflict: %v", err)
	}
}

func TestPerTaskMountPointsAreAllMounted(t *testing.T) {
	// Every path checkRootNotInUse treats as exclusive has to be one the
	// driver mounts for every task, or the check would never fire.
	cfg := &drivers.TaskConfig{Name: "web", AllocDir: "/var/nomad/alloc/x"}
	mounts := taskMounts(cfg, defaultTaskConfig(), &Config{}, NetworkInherit)

	mounted := map[string]bool{}
	for _, m := range mounts {
		mounted[m.Target] = true
	}
	for _, p := range perTaskMountPoints {
		if !mounted[p] {
			t.Errorf("%q is treated as per-task but is not mounted for every task", p)
		}
	}
}

// TestConfineMounts is the regression test for a job null-mounting any part of
// the host into its jail.
func TestConfineMounts(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, secret := filepath.Join(base, "data"), filepath.Join(base, "secret")
	for _, dir := range []string{data, secret} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A link inside what the job is allowed, to what it is not.
	escape := filepath.Join(data, "escape")
	if err := os.Symlink(secret, escape); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(data, "inside")
	if err := os.Symlink(data, inside); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{AllowedMounts: []string{data}}
	tests := []struct {
		name    string
		cfg     *Config
		mount   MountConfig
		want    string
		wantErr string
	}{
		{name: "an allowed directory", cfg: cfg, mount: MountConfig{Source: data, Target: "/data"}, want: data},
		{
			name: "a directory that is not allowed", cfg: cfg,
			mount: MountConfig{Source: secret, Target: "/s"}, wantErr: "allowed_mounts",
		},
		{
			name: "the host's root", cfg: cfg,
			mount: MountConfig{Source: "/", Target: "/host"}, wantErr: "allowed_mounts",
		},
		{
			name: "a link out of an allowed directory", cfg: cfg,
			mount: MountConfig{Source: escape, Target: "/s"}, wantErr: "allowed_mounts",
		},
		{
			name: "a link within an allowed directory is mounted by its real path", cfg: cfg,
			mount: MountConfig{Source: inside, Target: "/data"}, want: data,
		},
		{
			name: "nothing allowed", cfg: &Config{},
			mount: MountConfig{Source: data, Target: "/data"}, wantErr: "sets no allowed_mounts",
		},
		{
			name: "nothing listed, job authors trusted", cfg: &Config{AllowPrivileged: true},
			mount: MountConfig{Source: secret, Target: "/s"}, want: secret,
		},
		{
			name: "a source that does not exist", cfg: cfg,
			mount: MountConfig{Source: filepath.Join(data, "nope"), Target: "/n"}, wantErr: "no such file",
		},
		{
			name: "a tmpfs has no source to confine", cfg: &Config{},
			mount: MountConfig{Type: "tmpfs", Target: "/tmp"}, want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := confineMounts([]MountConfig{tc.mount}, tc.cfg)
			checkErr(t, err, tc.wantErr)
			if tc.wantErr != "" {
				return
			}
			if got[0].Source != tc.want {
				t.Errorf("source = %q, want %q", got[0].Source, tc.want)
			}
		})
	}
}

// TestMountAllCannotBeGivenAnotherSource checks that even if an option naming
// another source reached mountAll, the source that was checked is the one
// mounted.
func TestMountAllCannotBeGivenAnotherSource(t *testing.T) {
	requireRoot(t)

	root, source, other := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "checked"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "unchecked"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	done, err := mountAll(root, []mountSpec{{
		Type:    "nullfs",
		Source:  source,
		Target:  "/m",
		Options: map[string]string{"target": other},
	}}, hclog.NewNullLogger())
	t.Cleanup(func() {
		for _, m := range done {
			_ = jail.Unmount(m, jail.MountForce)
		}
	})
	if err != nil {
		t.Fatalf("mountAll: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "m", "checked")); err != nil {
		t.Errorf("the checked source is not what was mounted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "m", "unchecked")); err == nil {
		t.Error("an option replaced the source that had been checked")
	}
}
