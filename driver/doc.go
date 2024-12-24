// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

// Package driver implements a Nomad task driver that runs tasks in FreeBSD
// jails.
//
// A task becomes a jail.  The driver mounts the task's allocation directories
// into the jail's root with nullfs(5), creates the jail with jail_set(2),
// configures its network, and starts the task's command in it with jexec(8)
// under Nomad's shared executor.  What it creates is recorded in a jailState
// kept in the task handle, so that a restarted driver can still supervise and
// tear down its tasks.
//
// The driver runs on FreeBSD only.  Elsewhere the package builds, for the sake
// of its portable tests, but has no driver in it.
package driver
