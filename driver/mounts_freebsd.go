// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/allocdir"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/jail/nomad-driver/jail"
	"golang.org/x/sys/unix"
)

// Mount flags the driver uses.
const (
	jailMountReadOnly = jail.MountReadOnly
	jailMountNoSUID   = jail.MountNoSUID
	jailMountNoExec   = jail.MountNoExec
)

// taskDevDirPath is where a jail's devfs is mounted.  The task's own
// directories go where allocdir's *ContainerPath constants say, which is where
// Nomad points NOMAD_ALLOC_DIR and the rest for a driver with image isolation.
const taskDevDirPath = "/dev"

// mountSpec is a filesystem to mount in a jail, resolved to host paths.
type mountSpec struct {
	// Type is the filesystem name: nullfs, devfs, fdescfs, ...
	Type string
	// Source is the host path of a nullfs mount.
	Source string
	// Target is the absolute path in the jail.
	Target string
	// Flags are MNT_* flags.
	Flags int
	// Options are filesystem options.
	Options map[string]string
	// Required says whether failing to mount this fails the task.
	Required bool
}

// taskMounts lists the filesystems a task's jail needs, in mounting order: the
// task's own directories before anything the job asked for, so that a job
// cannot shadow them.
func taskMounts(cfg *drivers.TaskConfig, tc *TaskConfig, dcfg *Config, mode string) []mountSpec {
	dirs := cfg.TaskDir()
	var mounts []mountSpec

	if tc.MountDevfs {
		// The ruleset is what keeps a jail's /dev from being the
		// host's.  StartTask has checked that this one has rules in it.
		mounts = append(mounts, mountSpec{
			Type:     "devfs",
			Target:   taskDevDirPath,
			Options:  map[string]string{"ruleset": strconv.Itoa(devfsRuleset(tc, dcfg, mode))},
			Required: true,
		})
	}

	// Nomad writes a task's templates, artifacts and secrets into these.
	// secrets holds credentials and nothing to run, hence nosuid and
	// noexec.
	mounts = append(mounts,
		mountSpec{Type: "nullfs", Source: dirs.SharedAllocDir, Target: allocdir.SharedAllocContainerPath, Required: true},
		mountSpec{Type: "nullfs", Source: dirs.LocalDir, Target: allocdir.TaskLocalContainerPath, Required: true},
		mountSpec{
			Type:     "nullfs",
			Source:   dirs.SecretsDir,
			Target:   allocdir.TaskSecretsContainerPath,
			Flags:    jailMountNoSUID | jailMountNoExec,
			Required: true,
		},
	)

	if tc.MountFdescfs {
		mounts = append(mounts, mountSpec{Type: "fdescfs", Target: "/dev/fd", Required: true})
	}
	if tc.MountProcfs {
		mounts = append(mounts, mountSpec{Type: "procfs", Target: "/proc", Required: true})
	}

	// The job's own mount blocks.
	for _, m := range tc.Mounts {
		spec := mountSpec{
			Type:     m.Type,
			Source:   m.Source,
			Target:   m.Target,
			Options:  m.Options.merged(),
			Required: true,
		}
		if spec.Type == "" {
			spec.Type = "nullfs"
		}
		if m.Readonly {
			spec.Flags |= jailMountReadOnly
		}
		mounts = append(mounts, spec)
	}

	// Nomad's volume_mount and mount stanzas, already resolved to host
	// paths.
	for _, m := range cfg.Mounts {
		spec := mountSpec{
			Type:     "nullfs",
			Source:   m.HostPath,
			Target:   m.TaskPath,
			Required: true,
		}
		if m.Readonly {
			spec.Flags |= jailMountReadOnly
		}
		mounts = append(mounts, spec)
	}

	return mounts
}

// checkDevfsRuleset refuses a devfs ruleset that has no rules in it.
//
// The kernel does not.  Given a ruleset it does not have, devfs_ruleset_use()
// creates it, empty, and an empty ruleset hides nothing: the jail's /dev is
// then the host's, disks and memory included.
func checkDevfsRuleset(ctx context.Context, logger hclog.Logger, ruleset int) error {
	out, err := run(ctx, logger, pathDevfs, "rule", "-s", strconv.Itoa(ruleset), "show")
	if err != nil {
		return fmt.Errorf("reading devfs ruleset %d: %w", ruleset, err)
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("devfs ruleset %d has no rules loaded, so a /dev mounted with it "+
			"would show the jail every device on the host; load it with devfs(8), "+
			"which devfs_load_rulesets in rc.conf(5) does at boot", ruleset)
	}
	return nil
}

// confineMounts holds the host directories a job asked to have null-mounted
// against allowed_mounts.  It returns the mounts with each source replaced by
// its real path, so that what is mounted is what was checked.  A volume_mount
// does not come this way: the operator defined the volume.
func confineMounts(mounts []MountConfig, dcfg *Config) ([]MountConfig, error) {
	out := make([]MountConfig, len(mounts))
	for i, m := range mounts {
		out[i] = m
		if m.Type != "" && m.Type != "nullfs" {
			continue
		}
		source, err := filepath.EvalSymlinks(m.Source)
		if err != nil {
			return nil, fmt.Errorf("mount[%d]: source: %w", i, err)
		}
		if err := dcfg.pathAllowed("allowed_mounts", source, dcfg.AllowedMounts); err != nil {
			return nil, fmt.Errorf("mount[%d]: source: %w", i, err)
		}
		out[i].Source = source
	}
	return out, nil
}

// mountAll mounts a task's filesystems under root, creating their mount points.
// It returns what it mounted, in order, so that a failure part way can be
// undone.
func mountAll(root string, specs []mountSpec, logger hclog.Logger) ([]string, error) {
	var done []string

	for _, spec := range specs {
		target, err := resolveUnder(root, spec.Target)
		if err != nil {
			return done, err
		}

		if spec.Type == "nullfs" {
			if _, err := os.Stat(spec.Source); err != nil {
				if !spec.Required && os.IsNotExist(err) {
					logger.Warn("skipping mount, source does not exist",
						"source", spec.Source, "target", spec.Target)
					continue
				}
				return done, fmt.Errorf("mount source %s: %w", spec.Source, err)
			}
		}

		if err := os.MkdirAll(target, 0o755); err != nil {
			// A read-only image cannot gain mount points.  Say so,
			// rather than EROFS.
			if errors.Is(err, unix.EROFS) {
				return done, fmt.Errorf("the jail root is read-only and has no %s "+
					"to mount on; a read-only image needs its mount points to exist already",
					spec.Target)
			}
			return done, fmt.Errorf("creating mount point %s inside the jail: %w", spec.Target, err)
		}

		opts := spec.Options
		if spec.Type == "nullfs" {
			// "target" is what nullfs mounts.  It is set last, so
			// that no option can name another.
			opts = make(map[string]string, len(spec.Options)+1)
			for k, v := range spec.Options {
				opts[k] = v
			}
			opts["target"] = spec.Source
		}
		if err := jail.Mount(spec.Type, target, spec.Flags, opts); err != nil {
			return done, err
		}
		done = append(done, target)
	}

	return done, nil
}

// perTaskMountPoints are the paths in a jail root that belong to one task.
// Nothing else mounts them, which makes them the test for a root being in use.
var perTaskMountPoints = []string{
	allocdir.SharedAllocContainerPath,
	allocdir.TaskLocalContainerPath,
	allocdir.TaskSecretsContainerPath,
}

// checkRootNotInUse refuses a jail root that another task is using.
//
// Without it a second task naming the same path would have its /alloc, /local
// and /secrets mounted over the first's.  Nothing fails: the first task just
// starts reading the second's directories.
func checkRootNotInUse(root string) error {
	mounts, err := jail.Mounts(root)
	if err != nil {
		return err
	}
	inUse := make(map[string]bool, len(mounts))
	for _, m := range mounts {
		if m.Type == "nullfs" {
			inUse[m.On] = true
		}
	}

	for _, inner := range perTaskMountPoints {
		point := filepath.Join(root, inner)
		if !inUse[point] {
			continue
		}
		return fmt.Errorf("the jail root %s is already in use by another allocation, "+
			"which has its own %s mounted there; give each allocation a root of its own "+
			"with zfs_clone, or share the image read-only with readonly_rootfs",
			root, inner)
	}
	return nil
}

// driverMountPoints are the paths in a jail root the driver may have mounted,
// for tearing down a jail found on the system with no record of its mounts.
func driverMountPoints(root string) []string {
	inner := append([]string{taskDevDirPath}, perTaskMountPoints...)
	// After /dev, so that teardown, which goes in reverse, takes /dev/fd
	// first.
	inner = append(inner, "/dev/fd", "/proc")
	out := make([]string, 0, len(inner))
	for _, p := range inner {
		out = append(out, filepath.Join(root, p))
	}
	return out
}

// unmountAll unmounts a task's filesystems.
//
// A root the driver made, a ZFS clone or a read-only null mount, is the task's
// whole, and everything under it goes, including what a task with allow.mount
// mounted itself.  A root the job named is not: a thin jail's image may have
// mounts of its own, so only what the driver mounted goes.
func unmountAll(st *jailState) error {
	if st == nil || st.Root == "" {
		return nil
	}

	targets := st.Mounts
	if st.Dataset != "" || ownsRootMount(st) {
		targets = []string{st.Root}
	}

	var errs []error
	// In reverse, so that a mount made inside an earlier one goes first.
	for i := len(targets) - 1; i >= 0; i-- {
		if err := sweep(targets[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// How long sweep gives a filesystem to stop being busy before forcing it, and
// how often it looks.
const (
	unmountGrace    = 2 * time.Second
	unmountInterval = 10 * time.Millisecond
)

// sweep unmounts a mount point and everything below it.
//
// jail_remove(2) signals the jail's processes and returns, and until they have
// gone their open files keep its filesystems busy.  That takes milliseconds, so
// sweep waits for it before reaching for MNT_FORCE.
func sweep(path string) error {
	_, err := unmountPatiently(path)
	return err
}

// unmountPatiently is sweep, reporting whether it had to force anything.
func unmountPatiently(path string) (forced bool, err error) {
	deadline := time.Now().Add(unmountGrace)
	for {
		err := jail.UnmountAll(path, 0)
		if err == nil {
			return false, nil
		}
		if !errors.Is(err, unix.EBUSY) || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(unmountInterval)
	}
	return true, jail.UnmountAll(path, jail.MountForce)
}

// ownsRootMount reports whether the driver mounted the jail root itself, rather
// than being pointed at it by the job.
func ownsRootMount(st *jailState) bool {
	return slices.Contains(st.Mounts, st.Root)
}

// resolveUnder turns a path in the jail into a host path under root, refusing
// any that would escape.  The path comes from a job, so ".." and a symlink
// planted in the image both have to be allowed for.
func resolveUnder(root, inner string) (string, error) {
	if !filepath.IsAbs(inner) {
		return "", fmt.Errorf("%q is not an absolute path inside the jail", inner)
	}
	joined := filepath.Join(root, filepath.Clean(inner))
	if !pathWithin(joined, filepath.Clean(root)) {
		return "", fmt.Errorf("%q escapes the jail root", inner)
	}

	// Resolve the deepest ancestor that exists, so that a symlink in the
	// image cannot redirect the mount.  The path itself need not exist yet.
	probe := joined
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			if !pathWithin(resolved, filepath.Clean(root)) {
				return "", fmt.Errorf("%q resolves to %q, outside the jail root", inner, resolved)
			}
			return filepath.Join(append([]string{resolved}, tail...)...), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolving %q inside the jail: %w", inner, err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return joined, nil
		}
		tail = append([]string{filepath.Base(probe)}, tail...)
		probe = parent
	}
}

// writeResolvConf writes the task's DNS configuration to /etc/resolv.conf in
// the jail, which is where a jailed task's resolver looks: a jail has no DNS
// namespace of its own.
func writeResolvConf(root string, dns *drivers.DNSConfig) error {
	if dns == nil || (len(dns.Servers) == 0 && len(dns.Searches) == 0 && len(dns.Options) == 0) {
		return nil
	}

	target, err := resolveUnder(root, "/etc/resolv.conf")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("creating /etc inside the jail: %w", err)
	}

	var b strings.Builder
	b.WriteString("# Generated by the Nomad jail task driver.\n")
	if len(dns.Searches) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(dns.Searches, " "))
	}
	for _, s := range dns.Servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	for _, o := range dns.Options {
		fmt.Fprintf(&b, "options %s\n", o)
	}

	if err := os.WriteFile(target, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("writing resolv.conf inside the jail: %w", err)
	}
	return nil
}
