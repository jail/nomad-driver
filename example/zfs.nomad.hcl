# Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
#
# SPDX-License-Identifier: BSD-2-Clause

# A task rooted at a ZFS clone of a snapshot, made when the task starts and
# destroyed with it.  The plugin configuration has to name a zfs_parent.

job "zfs-example" {
  type = "batch"

  group "example" {
    task "shell" {
      driver = "jail"

      config {
        zfs_clone = "zroot/jails/base@ready"
        command   = "/bin/sh"
        args      = ["-c", "/bin/df -h / && /usr/bin/touch /writable && echo the root is writable"]
      }
    }
  }
}
