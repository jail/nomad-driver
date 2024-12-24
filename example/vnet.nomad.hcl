# Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
#
# SPDX-License-Identifier: BSD-2-Clause

# A task in a vnet jail: a network stack of its own, reached over an epair(4)
# on a host bridge.  A service registered here is advertised at the jail's
# address, not the host's.
#
# The bridge and the gateway are the operator's to provide:
#
#	ifconfig bridge create name nomadbr0
#	ifconfig nomadbr0 inet 10.88.0.1/24 up
#	sysctl net.inet.ip.forwarding=1
#
# and a nat rule in pf.conf(5) if tasks are to reach beyond the host.

job "vnet-example" {
  type = "service"

  group "example" {
    task "shell" {
      driver = "jail"

      config {
        path         = "/jails/base"
        command      = "/bin/sh"
        args         = ["-c", "while :; do /sbin/ifconfig; /bin/sleep 30; done"]
        network_mode = "vnet"

        vnet {
          bridge  = "nomadbr0"
          address = "10.88.0.10/24"
          gateway = "10.88.0.1"
        }
      }

      resources {
        cpu    = 100
        memory = 128
      }
    }
  }
}
