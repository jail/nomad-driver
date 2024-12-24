# Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
#
# SPDX-License-Identifier: BSD-2-Clause

# A single-node Nomad agent running the jail driver.  Start it with
#
#	nomad agent -dev -network-interface=lo0 \
#	    -config=./example/agent.hcl -plugin-dir=$(pwd)
#
# after "make build".  -dev otherwise looks for an interface named "lo".

log_level = "DEBUG"

client {
  # Nomad cannot read the CPU clock on every FreeBSD platform.  On arm64 it
  # finds 0 MHz, and every task fails to place with "Dimension cpu exhausted".
  # Stating the total, cores times MHz, works around it.
  cpu_total_compute = 8000
}

# Named after the plugin binary, not the driver: Nomad matches this against the
# file name in -plugin-dir.  Jobs say driver = "jail".  Nomad up to 1.10 warns
# and ignores a block it cannot match; from 1.11 it does not load the plugin.
plugin "jail-nomad-driver" {
  config {
    # Where a job may root a jail.  Leave it unset only where every job author
    # is trusted with root on the node.
    allowed_paths = ["/jails"]

    # Parent of the clones made for zfs_clone.
    zfs_parent = "zroot/jails/nomad"

    # The bridge a vnet task's host leg joins.
    bridge = "nomadbr0"

    # Jobs may not raise allow.* flags, set raw jail parameters or add rctl(8)
    # rules unless this is on.
    allow_privileged = false

    # How a jail is networked when the job does not say.
    default_network_mode = "inherit"
  }
}
