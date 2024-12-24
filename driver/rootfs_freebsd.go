// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/jail/nomad-driver/jail"
)

// rootfsMountDir is where, in a task's own directory, a derived root is
// mounted.  Nomad removes it with the allocation.
const rootfsMountDir = "jail"

// prepareRootfs works out the jail's root, creating it if it is to be derived,
// and records what it created in st:
//
//   - path is used as it is.
//   - path with readonly_rootfs is null-mounted read-only in the task's
//     directory, so its mount points have to exist already.
//   - zfs_clone is cloned into a dataset of the task's own, mounted in the
//     task's directory and destroyed with the task.
func prepareRootfs(ctx context.Context, logger hclog.Logger, cfg *drivers.TaskConfig, tc *TaskConfig, dcfg *Config, st *jailState) error {
	switch {
	case tc.ZFSClone != "":
		return cloneRootfs(ctx, logger, cfg, tc, dcfg, st)

	case tc.ReadonlyRootfs:
		image, err := resolveRootfsDir(tc.Path, dcfg)
		if err != nil {
			return err
		}
		target, err := taskRootfsMount(cfg)
		if err != nil {
			return err
		}
		if err := jail.MountNullfs(image, target, jail.MountReadOnly); err != nil {
			return err
		}
		st.Root = target
		st.Mounts = append(st.Mounts, target)
		return nil

	default:
		root, err := resolveRootfsDir(tc.Path, dcfg)
		if err != nil {
			return err
		}
		st.Root = root
		return nil
	}
}

// resolveRootfsDir checks that a job's jail root is a directory and returns its
// real path.  The kernel reports real paths, so a root reached through a
// symlink would match nothing in the mount table; and it is the real path that
// is held against allowed_paths, or a symlink would walk through it.
func resolveRootfsDir(path string, dcfg *Config) (string, error) {
	root, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("jail root %s: %w", path, err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("jail root %s: %w", path, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("jail root %s is not a directory", path)
	}
	if root == "/" {
		return "", fmt.Errorf("jail root %s resolves to the host's root directory", path)
	}
	// Again, as resolved.
	if err := checkAllowedPath(root, dcfg.AllowedPaths); err != nil {
		return "", err
	}
	return root, nil
}

// cloneRootfs clones a snapshot into a dataset of the task's own and mounts it
// in the task's directory.
func cloneRootfs(ctx context.Context, logger hclog.Logger, cfg *drivers.TaskConfig, tc *TaskConfig, dcfg *Config, st *jailState) error {
	dataset := dcfg.ZFSParent + "/" + st.Name
	target, err := taskRootfsMount(cfg)
	if err != nil {
		return err
	}

	// A clone left behind by a crash is in the way.
	if exists, err := datasetExists(ctx, logger, dataset); err != nil {
		return err
	} else if exists {
		logger.Warn("destroying a ZFS clone left behind by a previous run", "dataset", dataset)
		if err := destroyDataset(ctx, logger, dataset); err != nil {
			return err
		}
	}

	if _, err := run(ctx, logger, pathZFS, "clone",
		"-o", "mountpoint="+target, tc.ZFSClone, dataset); err != nil {
		return fmt.Errorf("cloning %s: %w", tc.ZFSClone, err)
	}
	// Recorded before anything below can fail, so that teardown destroys
	// the clone.
	st.Dataset = dataset
	st.Root = target

	// The clone is mounted by now unless a parent has canmount=noauto or
	// the like.
	if mounted, err := datasetMounted(ctx, logger, dataset); err != nil {
		return err
	} else if !mounted {
		if _, err := run(ctx, logger, pathZFS, "mount", dataset); err != nil {
			return fmt.Errorf("mounting %s: %w", dataset, err)
		}
	}

	if tc.ReadonlyRootfs {
		if _, err := run(ctx, logger, pathZFS, "set", "readonly=on", dataset); err != nil {
			return fmt.Errorf("making %s read-only: %w", dataset, err)
		}
	}
	return nil
}

// taskRootfsMount creates the mount point of a derived jail root in the task's
// directory and returns its real path.
func taskRootfsMount(cfg *drivers.TaskConfig) (string, error) {
	target := filepath.Join(cfg.TaskDir().Dir, rootfsMountDir)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", fmt.Errorf("creating the jail root mount point: %w", err)
	}
	// The kernel reports real paths; see resolveRootfsDir.
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("resolving the jail root mount point: %w", err)
	}
	return resolved, nil
}

func datasetExists(ctx context.Context, logger hclog.Logger, dataset string) (bool, error) {
	_, err := run(ctx, logger, pathZFS, "list", "-H", "-o", "name", dataset)
	if err == nil {
		return true, nil
	}
	// zfs list has no exit status for "no such dataset".
	if strings.Contains(err.Error(), "does not exist") {
		return false, nil
	}
	return false, fmt.Errorf("looking for dataset %s: %w", dataset, err)
}

func datasetMounted(ctx context.Context, logger hclog.Logger, dataset string) (bool, error) {
	out, err := run(ctx, logger, pathZFS, "list", "-H", "-o", "mounted", dataset)
	if err != nil {
		return false, fmt.Errorf("checking whether %s is mounted: %w", dataset, err)
	}
	return strings.TrimSpace(out) == "yes", nil
}

// destroyDataset destroys a per-task clone.
func destroyDataset(ctx context.Context, logger hclog.Logger, dataset string) error {
	if dataset == "" {
		return nil
	}
	if _, err := run(ctx, logger, pathZFS, "destroy", "-f", "-r", dataset); err != nil {
		if exists, cerr := datasetExists(ctx, logger, dataset); cerr == nil && !exists {
			return nil
		}
		return fmt.Errorf("destroying %s: %w", dataset, err)
	}
	return nil
}
