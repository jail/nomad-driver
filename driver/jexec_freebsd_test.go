// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"os/exec"
	"strings"
	"testing"
)

// TestJexecSupportsWorkDirMatchesTheRealJexec checks the probe against the
// usage of the jexec(8) installed here.
func TestJexecSupportsWorkDirMatchesTheRealJexec(t *testing.T) {
	out, _ := exec.Command(pathJexec).CombinedOutput()
	usage := string(out)
	if !strings.Contains(usage, "usage: jexec") {
		t.Skipf("%s did not print a usage line: %q", pathJexec, usage)
	}

	want := strings.Contains(usage, jexecWorkDirFlag)
	if got := jexecSupportsWorkDir(); got != want {
		t.Errorf("jexecSupportsWorkDir() = %v, but the usage line says %v:\n%s", got, want, usage)
	}
	t.Logf("this system's jexec takes -d: %v", want)
}

// TestJexecRejectsWorkDirWhenUnsupported records what the fallback is for: an
// older jexec has no -d.
func TestJexecRejectsWorkDirWhenUnsupported(t *testing.T) {
	if !jexecSupportsWorkDir() {
		out, err := exec.Command(pathJexec, "-d", "/srv", "0", "/bin/sh").CombinedOutput()
		t.Logf("older jexec refused -d as expected: %v: %s", err, out)
	}
}
