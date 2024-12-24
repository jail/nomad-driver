// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"bytes"
	"context"
	"os/exec"
	"sync"
)

// jexecWorkDirFlag is how jexec(8)'s usage shows its working directory option.
const jexecWorkDirFlag = "-d working-directory"

// jexecSupportsWorkDir reports whether this system's jexec(8) takes -d, which
// it gained in FreeBSD 14.3 and 15.0.  It asks jexec rather than
// kern.osreldate, which says nothing of a userland that differs from the
// kernel: run with no arguments, jexec prints its usage.
var jexecSupportsWorkDir = sync.OnceValue(func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// jexec exits non-zero here; the output is what matters.
	out, _ := exec.CommandContext(ctx, pathJexec).CombinedOutput()
	return bytes.Contains(out, []byte(jexecWorkDirFlag))
})
