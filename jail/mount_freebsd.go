// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Mount flags; the rest of MNT_* is in x/sys/unix.
const (
	MountReadOnly = unix.MNT_RDONLY
	MountNoSUID   = unix.MNT_NOSUID
	MountNoExec   = unix.MNT_NOEXEC
	MountForce    = unix.MNT_FORCE
)

// Mount mounts a filesystem with nmount(2).  opts are filesystem options as in
// fstab(5); one with an empty value is passed as a flag.
func Mount(fstype, target string, flags int, opts map[string]string) error {
	var iov iovecs
	iov.add("fstype", nulTerminate(fstype))
	iov.add("fspath", nulTerminate(target))

	// Sorted, so that the call and any error from it are reproducible.
	names := make([]string, 0, len(opts))
	for name := range opts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v := opts[name]; v == "" {
			iov.add(name, nil)
		} else {
			iov.add(name, nulTerminate(v))
		}
	}
	msg := iov.errmsg()

	if _, _, errno := unix.Syscall(unix.SYS_NMOUNT,
		uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(flags)); errno != 0 {
		return &Error{
			Op:  fmt.Sprintf("nmount %s on %s", fstype, target),
			Msg: trimNul(msg),
			Err: errno,
		}
	}
	return nil
}

// MountNullfs mounts source over target with nullfs(5).
func MountNullfs(source, target string, flags int) error {
	return Mount("nullfs", target, flags, map[string]string{"target": source})
}

// MountDevfs mounts a devfs(5) on target.  A non-zero ruleset restricts which
// device nodes appear in it; see devfs.rules(5).  Ruleset 0 hides nothing.
func MountDevfs(target string, ruleset int, flags int) error {
	opts := map[string]string{}
	if ruleset != 0 {
		opts["ruleset"] = fmt.Sprint(ruleset)
	}
	return Mount("devfs", target, flags, opts)
}

// Unmount unmounts the filesystem at target.  A path that is not a mount point
// is not an error, so that cleanup is idempotent.
func Unmount(target string, flags int) error {
	err := unix.Unmount(target, flags)
	switch {
	case err == nil,
		errors.Is(err, unix.EINVAL), // not a mount point
		errors.Is(err, unix.ENOENT): // already gone
		return nil
	}
	return fmt.Errorf("unmount %s: %w", target, err)
}

// MountInfo describes a mounted filesystem, as statfs(2) reports it.
type MountInfo struct {
	// Type is the filesystem name: nullfs, devfs, zfs, ...
	Type string
	// From is what was mounted: a nullfs source, a ZFS dataset.
	From string
	// On is the mount point.
	On string
}

// Mounts returns the filesystems mounted at or below root, deepest first, so
// that unmounting them in order takes a child before its parent.
func Mounts(root string) ([]MountInfo, error) {
	root = filepath.Clean(root)

	// The mount table can grow between asking for the count and for the
	// entries, so leave some headroom.
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, fmt.Errorf("getfsstat: %w", err)
	}
	buf := make([]unix.Statfs_t, n+8)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, fmt.Errorf("getfsstat: %w", err)
	}

	var out []MountInfo
	for _, fs := range buf[:n] {
		on := unix.ByteSliceToString(fs.Mntonname[:])
		if root != "/" && on != root && !strings.HasPrefix(on, root+string(filepath.Separator)) {
			continue
		}
		out = append(out, MountInfo{
			Type: unix.ByteSliceToString(fs.Fstypename[:]),
			From: unix.ByteSliceToString(fs.Mntfromname[:]),
			On:   on,
		})
	}

	// Deepest first: a child's path is its parent's plus a separator, so it
	// sorts after it.
	sort.Slice(out, func(i, j int) bool { return out[i].On > out[j].On })
	return out, nil
}

// MountsUnder returns the mount points at or below root, deepest first.
func MountsUnder(root string) ([]string, error) {
	mounts, err := Mounts(root)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, m.On)
	}
	return out, nil
}

// UnmountAll unmounts every filesystem at or below root, children first.  It
// returns the first error but keeps going.
func UnmountAll(root string, flags int) error {
	mounts, err := MountsUnder(root)
	if err != nil {
		return err
	}
	var firstErr error
	for _, m := range mounts {
		if err := Unmount(m, flags); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
