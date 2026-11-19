// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

// jailState records what the driver created for a task.  It is kept in the task
// handle, so every field has to survive msgpack.
type jailState struct {
	// Name is the jail's name, derived from the allocation and task.
	Name string

	// AllocDir is the allocation's shared directory.  Nomad removes it
	// with the allocation, which is how a jail nobody is coming back for
	// is known.
	AllocDir string

	// JID is the jail ID the kernel assigned, kept to be reported.  The
	// kernel reuses IDs, so the jail is always found by Name.
	JID int

	// Root is the jail's root: the task's path, the mount point of its ZFS
	// clone, or the read-only null mount of its image.
	Root string

	// Mounts are the filesystems mounted in the jail, in order.
	Mounts []string

	// Dataset is a per-task ZFS clone to destroy, if any.
	Dataset string

	// Epair is the host leg of a vnet task's epair(4), epairHostName(Name),
	// and empty for any other task.  It is kept to be reported; teardown
	// derives the name again.
	Epair string

	// Bridge is the bridge the host leg was added to.
	Bridge string

	// Aliases are the addresses added to host interfaces for an alias-mode
	// jail, as ifaddrSpec strings.
	Aliases []string

	// RCTLRules are the rctl(8) rules added for the task.
	RCTLRules []string

	// IP is the address configured in a vnet jail, which Nomad registers
	// the task's services at.
	IP string
}
