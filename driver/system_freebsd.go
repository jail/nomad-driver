// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"golang.org/x/sys/unix"
)

// commandTimeout bounds the utilities the driver runs, so that a wedged
// ifconfig cannot wedge a task start.
const commandTimeout = 30 * time.Second

// run executes a host utility and returns its trimmed output.  The command is
// logged at trace level.
func run(ctx context.Context, logger hclog.Logger, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	logger.Trace("running command", "cmd", name, "args", args)
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return text, fmt.Errorf("%s %s: timed out after %s: %w",
				name, strings.Join(args, " "), commandTimeout, err)
		}
		if text == "" {
			return text, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
	}
	logger.Trace("command succeeded", "cmd", name, "output", text)
	return text, nil
}

// executable reports whether path is a file the driver could run.
func executable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// sysctlString reads a string sysctl, returning "" if it does not exist.
func sysctlString(name string) string {
	s, err := unix.Sysctl(name)
	if err != nil {
		return ""
	}
	return s
}

// sysctlInt reads an integer sysctl.  The second result is false if there is no
// such sysctl, which is how to tell that a kernel feature is absent.
func sysctlInt(name string) (int, bool) {
	v, err := unix.SysctlUint32(name)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// geteuid saves the tests an import of os.
func geteuid() int { return os.Geteuid() }
