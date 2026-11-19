// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"strings"

	"github.com/hashicorp/nomad/plugins/drivers"
)

// jexecCommand builds the command the executor launches.
//
// jexec(8) attaches to the jail and execs, so the process the executor
// supervises is the task itself.  The jail is named, since a jail ID outlives
// neither the jail nor a reboot, and the user is resolved in the jail's own
// passwd database.
//
// nativeWorkDir says whether jexec takes -d, as it does from FreeBSD 14.3 and
// 15.0.  Without it the only way to start outside the jail root is through a
// shell, which the image then has to have.
func jexecCommand(jail string, cfg *drivers.TaskConfig, tc *TaskConfig, nativeWorkDir bool) (string, []string) {
	args := make([]string, 0, 8+len(tc.Args))

	useShell := tc.WorkDir != "" && !nativeWorkDir
	if tc.WorkDir != "" && nativeWorkDir {
		args = append(args, "-d", tc.WorkDir)
	}
	if cfg.User != "" {
		args = append(args, "-U", cfg.User)
	}
	args = append(args, jail)

	if !useShell {
		return pathJexec, append(args, append([]string{tc.Command}, tc.Args...)...)
	}

	script := "cd " + shellQuote(tc.WorkDir) + " && exec " + shellQuote(tc.Command)
	for _, a := range tc.Args {
		script += " " + shellQuote(a)
	}
	return pathJexec, append(args, pathShell, "-c", script)
}

// shellQuote renders s as a single sh(1) word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
