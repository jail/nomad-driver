# FreeBSD Jails Nomad Task Driver

[Nomad](https://www.nomadproject.io) for
[FreeBSD jails](https://man.freebsd.org/cgi/man.cgi?jail(8)).

A task becomes a jail.  The driver works out the jail's root, mounts the task's
directories in it with `nullfs(5)` and a restricted `devfs(5)` on `/dev`,
creates the jail with `jail_set(2)`, configures its network, and starts the
task's command in it with `jexec(8)` under Nomad's shared executor, which
provides logs, statistics, signals and `nomad alloc exec` as it does for `exec`.

Jails are created through `jail(2)` directly, by the `jail` package here: a Go
binding that learns parameter types from the kernel's `security.jail.param`
sysctl tree, as `jailparam_init(3)` does.  Any parameter `jail(8)` takes can be
passed through, those of loadable modules included.

## Requirements

- FreeBSD, with the agent running as root.
- Nomad 1.9 or later on the client.  The driver is built against 1.11, and has
  been run against 1.9.6 and 1.11.3.
- Go 1.26 or later to build.
- `VIMAGE` for `network_mode = "vnet"`, which `GENERIC` has.
- ZFS for `zfs_clone`.
- FreeBSD 14.3 or 15.0 for `work_dir` without a shell in the image: that is when
  `jexec(8)` gained `-d`, which the driver probes for.  Without it the command
  is run through `/bin/sh`.
- `RACCT` and `RCTL` for memory limits, which `GENERIC` has, off until
  `kern.racct.enable=1` is set in `loader.conf(5)`.  Without them the task runs
  unlimited, with a warning; see `driver.jail.rctl`.

## Building

```bash
make build
```

That produces `jail-nomad-driver`, for FreeBSD whatever the host.  Put it in
the client's `plugin_dir` and configure it:

```hcl
plugin "jail-nomad-driver" {
  config {
    allowed_paths = ["/jails"]
    zfs_parent    = "zroot/jails/nomad"
    bridge        = "nomadbr0"
  }
}
```

The `plugin` block is named after the binary's file name, not the driver; jobs
say `driver = "jail"`.  Nomad up to 1.10 warns and ignores a block it cannot
match, and from 1.11 does not load the plugin.

`go test ./...` runs anywhere.  Tests that create jails, mount filesystems or
clone datasets skip themselves unless run as root on FreeBSD.

## Plugin configuration

| Field                  | Default     | Meaning                                                                      |
| ---------------------- | ----------- | ---------------------------------------------------------------------------- |
| `enabled`              | `true`      | Whether the driver fingerprints at all.                                      |
| `allowed_paths`        | unset       | Directories a job's `path` has to be at or below.                            |
| `allowed_mounts`       | unset       | Directories the `source` of a job's `mount` has to be at or below.           |
| `allowed_datasets`     | unset       | Datasets a job's `zfs_clone` has to be a snapshot of, or of a descendant of. |
| `allow_privileged`     | `false`     | Says job authors are trusted with root on the node; see below.               |
| `default_network_mode` | `"inherit"` | `network_mode` for a task that states none.                                  |
| `bridge`               | unset       | Bridge a `vnet` task's host leg joins, unless the task names one.            |
| `zfs_parent`           | unset       | Parent dataset of per-task clones.  Required for `zfs_clone`.                |
| `devfs_ruleset`        | unset       | `devfs.rules(5)` ruleset for every jail's `/dev`, instead of the stock ones. |
| `resource_limits`      | `true`      | Whether to apply `rctl(8)` rules.                                            |
| `gc { jail }`          | `true`      | Whether to reap orphaned jails at startup.                                   |

### What a job can reach

A job names things on the host: the directory its jail is rooted at, directories
to null-mount into it, a snapshot to clone its root from.  Each is held against
one of the `allowed_*` lists, and a list that is not set covers nothing.

Paths are compared as real paths, with symbolic links resolved on both sides.

`allow_privileged = true` says that job authors are trusted with root on the
node, which is what the settings it gates amount to: `allow`, `jail_params`,
`extra_rctl`, mount options beyond sizing a `tmpfs`, and an `enforce_statfs`
below 2.  It also lifts any `allowed_*` list that is not set; a list that is set
still binds.

Nomad's `volume_mount` is not held against `allowed_mounts`: the operator
defined the volume.

## Task configuration

### The process

| Field      | Default       | Meaning                        |
| ---------- | ------------- | ------------------------------ |
| `command`  | required      | Absolute path in the jail.     |
| `args`     | none          | Its arguments.                 |
| `work_dir` | the jail root | Working directory in the jail. |

The task's `user` is resolved in the jail, from its own `passwd` database, by
`jexec -U`.

### The root filesystem

| Field             | Default | Meaning                                                                                   |
| ----------------- | ------- | ----------------------------------------------------------------------------------------- |
| `path`            |         | An existing directory, used as the jail root, confined by `allowed_paths`.                |
| `zfs_clone`       |         | A `dataset@snapshot` to clone per task, confined by `allowed_datasets`.  Excludes `path`. |
| `readonly_rootfs` | `false` | Mount the image read-only.                                                                |

One of `path` and `zfs_clone` is required.

The driver mounts `/alloc`, `/local` and `/secrets` in the root, so a `path`
serves one allocation at a time, and a second that names it is refused.  For an
image many allocations run from, use `zfs_clone`, which gives each a writable
copy and destroys it with the task, or `readonly_rootfs`, which null-mounts the
image read-only in the task's directory and so needs its mount points to exist
in the image.

What the driver mounts goes with the task.  Under a root the driver made, a
clone or a read-only null mount, everything is unmounted, including what a task
with `allow.mount` mounted itself.  Under a root the job named, only what the
driver mounted is, so a thin jail's own mounts stay.

### Networking

`network_mode` is one of:

- `inherit`, the default, shares the host's stack and addresses
  (`ip4=inherit`).  The ports Nomad allocated on the host are the ports the task
  binds.
- `alias` confines the jail to the addresses in `ip4_addr` and `ip6_addr`
  (`ip4.addr`).  An entry may name a host interface and a prefix length, as in
  `em0|10.0.0.5/24`; the driver then adds and removes the alias with
  `ifconfig(8)`, as `jail(8)` does.
- `vnet` gives the jail a network stack of its own (`vnet=new`).  The driver
  makes an `epair(4)`, adds the host leg to a bridge, moves the other into the
  jail, and addresses and routes it there.  The address is reported to Nomad, so
  a service registered from the task is advertised at the jail's address.
  The jail's side is configured with `ifconfig -j` and `route -j`, which FreeBSD
  has from 13.5 and 14.0, so the image needs no network utilities.
- `none` gives the jail a network stack of its own with nothing in it but
  loopback (`vnet=new`), which is what Nomad's `mode = "none"` means.  Without
  `VIMAGE` it falls back to `ip4=disable`, `ip6=disable`, which is stricter: the
  task cannot open an IP socket at all, loopback included.

The `vnet` block takes `bridge`, `address`, `gateway`, `address6`, `gateway6`,
`mac` and `mtu`.  Addresses are in prefix form (`10.88.0.5/24`).  With no
`address` the interface is brought up and left to the task, for `dhclient(8)` or
a routing daemon.

The bridge and the gateway are the operator's to provide:

```bash
ifconfig bridge create name nomadbr0
ifconfig nomadbr0 inet 10.88.0.1/24 up
sysctl net.inet.ip.forwarding=1
```

and a `nat` rule in `pf.conf(5)` if tasks are to reach beyond the host.

The driver supports Nomad's `host`, `task` and `none` network isolation modes,
not `group`: Nomad has no CNI on FreeBSD, so a group `network` block with
`mode = "bridge"` has nothing to implement it.  Publishing a host port into a
`vnet` jail needs `rdr` rules in `pf.conf(5)`, which the driver does not manage.

### Filesystem and devices

| Field           | Default                | Meaning                                                                                                                         |
| --------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `mount_devfs`   | `true`                 | Mount `devfs(5)` on `/dev`.                                                                                                     |
| `devfs_ruleset` | `4`, or `5` for `vnet` | `devfsrules_jail`, or `devfsrules_jail_vnet`, which adds `bpf` for `dhclient(8)`.  Another needs `allow_privileged`.            |
| `mount_fdescfs` | `false`                | Mount `fdescfs(5)` on `/dev/fd`.                                                                                                |
| `mount_procfs`  | `false`                | Mount `procfs(5)` on `/proc`.                                                                                                   |
| `mount { ... }` | none                   | Repeatable: `source`, `target`, `type` (`nullfs` by default), `readonly`, `options`.  `source` is confined by `allowed_mounts`. |

The ruleset is all that keeps the host's devices out of a jail.  It is never 0,
and never one with no rules loaded: given a ruleset it does not have, the kernel
creates it, empty, and an empty ruleset hides nothing.  The driver checks first
and refuses the task, and fingerprints as undetected where its default ruleset
is not loaded, which is what `devfs_load_rulesets="NO"` in `rc.conf(5)` leads
to.

A task with a `device` block is refused.  What appears in a jail's `/dev` is
decided by the ruleset it was mounted with, so there is nothing to translate a
device request into.  Write a ruleset that exposes the device and name it in
the plugin's `devfs_ruleset`.

`/alloc`, `/local` and `/secrets` are mounted for every task, before anything a
job asked for, so that a job cannot shadow them; `/secrets` is `nosuid` and
`noexec`.  Nomad's `volume_mount` and `mount` are honoured.

`NOMAD_ALLOC_DIR`, `NOMAD_TASK_DIR` and `NOMAD_SECRETS_DIR` are `/alloc`,
`/local` and `/secrets`: the driver reports image filesystem isolation, and
Nomad does not pass the host's environment to such a task.

Nomad's `dns` block is written to `/etc/resolv.conf` in the jail.

### Security

| Field            | Default    | Meaning                                                                                        |
| ---------------- | ---------- | ---------------------------------------------------------------------------------------------- |
| `enforce_statfs` | `2`        | The kernel's default: the task sees only its own filesystems.  Lower needs `allow_privileged`. |
| `children_max`   | `0`        | No jails within the jail.                                                                      |
| `securelevel`    | the host's | `-1` to `3`.  Sent only when set.                                                              |
| `allow`          | none       | `allow.*` flags, unprefixed: `["mount", "raw_sockets"]`.  Needs `allow_privileged`.            |
| `jail_params`    | none       | Any other jail parameter.  Needs `allow_privileged`.  Those the driver derives are refused.    |

### Resources

| Field             | Default | Meaning                                                                                     |
| ----------------- | ------- | ------------------------------------------------------------------------------------------- |
| `resource_limits` | `true`  | Turn the task's Nomad resources into `rctl(8)` rules.                                       |
| `extra_rctl`      | none    | Extra rules, in full or from the resource on (`"pcpu:deny=50"`).  Needs `allow_privileged`. |
| `cpuset`          | `true`  | Pin the jail to the cores Nomad reserved, with `cpuset(1)`.                                 |

Memory becomes `memoryuse:deny`, of `memory_max` where the job set one.

CPU is not translated: Nomad counts MHz and `pcpu` is a percentage of a core, so
a conversion would be a guess at the node's clock.  A job can state a ceiling in
`extra_rctl`; reserved cores get a `cpuset`.

With resource accounting off, a limit the driver derived is skipped with a
warning, and a job that needs it can constrain on `driver.jail.rctl`.  A rule
the job asked for by name fails the task.

## Node attributes

| Attribute                      | Meaning                                             |
| ------------------------------ | --------------------------------------------------- |
| `driver.jail.version`          | `kern.osrelease`.                                   |
| `driver.jail.vnet`             | Whether the kernel has `VIMAGE`.                    |
| `driver.jail.zfs`              | Whether ZFS is available.                           |
| `driver.jail.rctl`             | Whether `rctl(8)` rules will be accepted.           |
| `driver.jail.nested`           | Whether the agent is itself in a jail.              |
| `driver.jail.jexec_workdir`    | Whether `jexec(8)` takes `-d`.                      |
| `driver.jail.bridge`           | The operator's default bridge, if set.              |
| `driver.jail.allow_privileged` | Whether privileged task configuration is permitted. |

The driver fingerprints as undetected, with the reason, where it could not start
a jail: not FreeBSD, not root, `jail_get(2)` failing, an agent in a jail whose
`children.max` is 0, a default `devfs` ruleset that is not loaded, or a `vnet`
default without `VIMAGE`.

## Examples

`example/` has an agent configuration and three jobs: `inherit` networking,
`vnet`, and a ZFS clone.

```bash
nomad agent -dev -network-interface=lo0 \
    -config=./example/agent.hcl -plugin-dir=$(pwd)
```

```bash
nomad job run ./example/example.nomad.hcl
```

`-dev` defaults `network-interface` to `lo`, which FreeBSD does not have.  Nor
can Nomad read the CPU clock on every FreeBSD platform: on arm64 it finds 0 MHz
and every task fails to place with `Dimension "cpu" exhausted`, so
`client { cpu_total_compute }` may be needed.

## Events

Besides Nomad's own, the driver emits a task event where it carried on but did
other than the job asked: a resource limit the kernel would not accept, DNS it
could not write into the image, and a jail reclaimed from an earlier run of the
task.

## Lifecycle and failure

What the driver creates for a task is recorded in the task handle as it goes.  A
start that fails part way undoes what it had done.  A restarted driver reads the
state back, finds the jail by name, and supervises and tears down a task it did
not start; `nomad alloc exec`, signals, statistics and logs go on working.

The driver never acts on an identifier it wrote down.  The kernel reuses jail
IDs and interface names, so a jail is always found by name, and the host leg of
a `vnet` task's `epair` is renamed to a name derived from the jail's.

Jail names are `nomad-<alloc>-<task>`, so a jail left by an earlier run of a
task is recognised and reclaimed when the task starts again.
`gc { jail = true }` also reaps, at startup, jails whose allocation directory
has gone: the agent was killed, and its allocations were collected while it was
down.

Not reclaimed after a crash, since nothing but the task handle records them:
aliases added for an `alias` task and, where Nomad forgets the allocation as
well, which in practice means `-dev`, the jail itself.

## Licensing

Each file states its licence in its header; see [COPYRIGHT](COPYRIGHT).
