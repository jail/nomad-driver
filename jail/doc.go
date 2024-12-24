// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

// Package jail is a pure Go binding for jail_set(2), jail_get(2),
// jail_attach(2) and jail_remove(2).
//
// Parameter types are read at run time from the security.jail.param sysctl
// tree, as jailparam_init(3) does, so parameters added by loadable modules need
// no support here.  Values are exchanged as strings in the syntax of
// jail.conf(5), and errors carry the kernel's "errmsg" when it supplies one.
package jail
