// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/hashicorp/nomad/plugins/drivers"
)

// jailNamePrefix marks the driver's jails, which is how one left behind by a
// crash is told from an operator's own.
const jailNamePrefix = "nomad-"

// allocIDShort is how much of an allocation's UUID goes into a jail name.
const allocIDShort = 8

// jailName derives the name of a task's jail from the allocation ID and the
// task name alone, so that a jail left behind by a crash can be recognised.
// The kernel reserves the dot, for jail hierarchies, so anything outside
// [A-Za-z0-9_-] is replaced.
func jailName(cfg *drivers.TaskConfig) string {
	alloc := strings.ReplaceAll(cfg.AllocID, "-", "")
	if len(alloc) > allocIDShort {
		alloc = alloc[:allocIDShort]
	}
	if alloc == "" {
		alloc = "noalloc"
	}
	return jailNamePrefix + alloc + "-" + sanitiseJailName(cfg.Name)
}

// maxTaskNamePart bounds the task's part of a jail name.
const maxTaskNamePart = 48

func sanitiseJailName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= maxTaskNamePart {
			break
		}
	}
	if b.Len() == 0 {
		return "task"
	}
	return b.String()
}

// isDriverJail reports whether a jail name belongs to this driver.
func isDriverJail(name string) bool {
	return strings.HasPrefix(name, jailNamePrefix)
}

// epairNamePrefix marks the host-side leg of every epair(4) the driver creates.
const epairNamePrefix = "nj"

// epairHostName derives the name of the host leg of a vnet task's epair(4) from
// the name of its jail.
//
// The kernel reuses epair units, so the name an epair is created with is
// somebody else's after a reboot.  A derived name can be recomputed by a driver
// that has lost its state, and names nothing but this driver's interfaces.  It
// is the prefix and 52 bits of SHA-256, to fit IFNAMSIZ; a collision makes the
// rename fail.
func epairHostName(jail string) string {
	const ifNameMax = 15

	sum := sha256.Sum256([]byte(jail))
	return epairNamePrefix + hex.EncodeToString(sum[:])[:ifNameMax-len(epairNamePrefix)]
}
