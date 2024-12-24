// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

// Base-system utilities the driver runs, by absolute path so as not to depend
// on the agent's PATH.
const (
	pathJexec    = "/usr/sbin/jexec"
	pathIfconfig = "/sbin/ifconfig"
	pathRoute    = "/sbin/route"
	pathZFS      = "/sbin/zfs"
	pathRCTL     = "/usr/bin/rctl"
	pathCpuset   = "/usr/bin/cpuset"
	pathShell    = "/bin/sh"
)
