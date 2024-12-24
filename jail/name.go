// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import (
	"fmt"
	"strings"
)

// A boolean parameter has an affirmative name and a negated one, with "no" in
// front of the last dot-separated component: "persist" and "nopersist",
// "allow.mount" and "allow.nomount".  These mirror noname() and nononame() in
// libjail.

// negateName returns the negated spelling of a boolean parameter name.
func negateName(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[:i+1] + "no" + name[i+1:]
	}
	return "no" + name
}

// affirmName is the inverse of negateName.
func affirmName(name string) (string, error) {
	i := strings.LastIndexByte(name, '.')
	if !strings.HasPrefix(name[i+1:], "no") {
		return "", fmt.Errorf("mismatched boolean: %s", name)
	}
	return name[:i+1] + name[i+3:], nil
}

// keyValueName returns the node a key/value parameter such as "env.FOO" hangs
// off, or "" if name has none.  It mirrors kvname() in libjail.
func keyValueName(name string) string {
	node, _, found := strings.Cut(name, ".")
	if !found {
		return ""
	}
	return node
}
