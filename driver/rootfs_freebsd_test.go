// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRootfsDir(t *testing.T) {
	base := t.TempDir()
	baseResolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(baseResolved, "image")
	if err := os.MkdirAll(image, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(baseResolved, "link")
	if err := os.Symlink(image, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(baseResolved, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("a directory resolves to itself", func(t *testing.T) {
		got, err := resolveRootfsDir(image, &Config{})
		if err != nil || got != image {
			t.Errorf("resolveRootfsDir = %q, %v; want %q", got, err, image)
		}
	})

	t.Run("a symlink resolves to its target", func(t *testing.T) {
		got, err := resolveRootfsDir(link, &Config{})
		if err != nil || got != image {
			t.Errorf("resolveRootfsDir = %q, %v; want %q", got, err, image)
		}
	})

	t.Run("a file is not a jail root", func(t *testing.T) {
		if _, err := resolveRootfsDir(file, &Config{}); err == nil {
			t.Error("a regular file was accepted as a jail root")
		}
	})

	t.Run("a path that does not exist", func(t *testing.T) {
		if _, err := resolveRootfsDir(filepath.Join(baseResolved, "nope"), &Config{}); err == nil {
			t.Error("a missing directory was accepted as a jail root")
		}
	})

	t.Run("the host root is refused", func(t *testing.T) {
		_, err := resolveRootfsDir("/", &Config{})
		if err == nil || !strings.Contains(err.Error(), "host's root") {
			t.Errorf("err = %v, want it to refuse the host root", err)
		}
	})

	t.Run("allowed_paths is rechecked after resolution", func(t *testing.T) {
		// The symlink is inside the permitted directory and its target
		// is not, which a check on the path as written would let
		// through.
		outside := t.TempDir()
		outsideResolved, err := filepath.EvalSymlinks(outside)
		if err != nil {
			t.Fatal(err)
		}
		escape := filepath.Join(image, "escape")
		if err := os.Symlink(outsideResolved, escape); err != nil {
			t.Fatal(err)
		}

		cfg := &Config{AllowedPaths: []string{image}}
		if _, err := resolveRootfsDir(escape, cfg); err == nil {
			t.Error("a symlink out of allowed_paths was accepted")
		}
		if _, err := resolveRootfsDir(image, cfg); err != nil {
			t.Errorf("a path inside allowed_paths was refused: %v", err)
		}
	})
}
