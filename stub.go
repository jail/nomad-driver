// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

//go:build !freebsd

// The driver needs jail(2), and so FreeBSD.  This lets the module build, vet
// and test anywhere else.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr,
		"jail-nomad-driver runs tasks in FreeBSD jails and cannot run on %s/%s\n",
		runtime.GOOS, runtime.GOARCH)
	os.Exit(1)
}
