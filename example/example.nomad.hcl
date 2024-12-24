# Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
#
# SPDX-License-Identifier: BSD-2-Clause

# A task in a jail that shares the host's network stack: the ports Nomad
# allocated on the host are the ports the task binds.

job "example" {
  type = "service"

  group "example" {
    task "shell" {
      driver = "jail"

      config {
        path    = "/jails/base"
        command = "/bin/sh"
        args    = ["-c", "while :; do echo \"$(/bin/hostname) $(/usr/bin/id -un) $NOMAD_TASK_DIR\"; /bin/sleep 5; done"]
      }

      resources {
        cpu    = 100
        memory = 128
      }
    }
  }
}
