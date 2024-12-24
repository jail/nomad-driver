// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
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
