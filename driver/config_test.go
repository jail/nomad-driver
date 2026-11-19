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

// defaultTaskConfig is a task configuration as the schema's defaults leave it
// once a job has named a command and a root.
func defaultTaskConfig() *TaskConfig {
	return &TaskConfig{
		Command:        "/bin/sh",
		Path:           "/jails/base",
		MountDevfs:     true,
		EnforceStatfs:  2,
		ChildrenMax:    0,
		Securelevel:    -1,
		ResourceLimits: true,
		Cpuset:         true,
	}
}

// defaultConfig is the plugin configuration of an operator who lets jobs root
// their jails under /jails, and nothing else.
func defaultConfig() *Config {
	return &Config{
		Enabled:            true,
		AllowedPaths:       []string{"/jails"},
		DefaultNetworkMode: NetworkInherit,
		ResourceLimits:     true,
		GC:                 GCConfig{Jail: true},
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "defaults"},
		{
			name:    "unknown network mode",
			mutate:  func(c *Config) { c.DefaultNetworkMode = "bridge" },
			wantErr: "default_network_mode",
		},
		{
			name:    "relative allowed path",
			mutate:  func(c *Config) { c.AllowedPaths = []string{"jails"} },
			wantErr: "absolute path",
		},
		{
			name:    "zfs_parent given as a path",
			mutate:  func(c *Config) { c.ZFSParent = "/zroot/jails" },
			wantErr: "dataset name",
		},
		{
			name:    "relative allowed mount",
			mutate:  func(c *Config) { c.AllowedMounts = []string{"data"} },
			wantErr: "absolute path",
		},
		{
			name:    "allowed dataset given as a path",
			mutate:  func(c *Config) { c.AllowedDatasets = []string{"/zroot/jails"} },
			wantErr: "dataset name",
		},
		{
			name: "all three lists",
			mutate: func(c *Config) {
				c.AllowedMounts = []string{"/data"}
				c.AllowedDatasets = []string{"zroot/jails/base"}
			},
		},
		{
			name:   "vnet default is allowed",
			mutate: func(c *Config) { c.DefaultNetworkMode = NetworkVnet },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfig()
			if tc.mutate != nil {
				tc.mutate(cfg)
			}
			err := cfg.Validate()
			checkErr(t, err, tc.wantErr)
		})
	}
}

func TestTaskConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TaskConfig)
		driver  func(*Config)
		wantErr string
	}{
		{name: "defaults"},
		{
			name:    "no command",
			mutate:  func(tc *TaskConfig) { tc.Command = "" },
			wantErr: "command is required",
		},
		{
			name:    "relative command",
			mutate:  func(tc *TaskConfig) { tc.Command = "sh" },
			wantErr: "absolute path",
		},
		{
			name:    "relative work_dir",
			mutate:  func(tc *TaskConfig) { tc.WorkDir = "srv" },
			wantErr: "absolute path",
		},
		{
			name:    "no root",
			mutate:  func(tc *TaskConfig) { tc.Path = "" },
			wantErr: "one of path or zfs_clone",
		},
		{
			name: "both roots",
			mutate: func(tc *TaskConfig) {
				tc.ZFSClone = "zroot/jails/base@ready"
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "zfs_clone without a snapshot",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/jails/base"
			},
			driver:  func(c *Config) { c.ZFSParent = "zroot/jails/nomad" },
			wantErr: "not a snapshot",
		},
		{
			name: "zfs_clone without zfs_parent",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/jails/base@ready"
			},
			wantErr: "needs zfs_parent",
		},
		{
			name: "zfs_clone with zfs_parent",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/jails/base@ready"
			},
			driver: func(c *Config) {
				c.ZFSParent = "zroot/jails/nomad"
				c.AllowedDatasets = []string{"zroot/jails/base"}
			},
		},
		{
			name: "zfs_clone with no allowed_datasets",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/jails/base@ready"
			},
			driver:  func(c *Config) { c.ZFSParent = "zroot/jails/nomad" },
			wantErr: "sets no allowed_datasets",
		},
		{
			name: "zfs_clone of a dataset the operator did not list",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/ROOT/default@backup"
			},
			driver: func(c *Config) {
				c.ZFSParent = "zroot/jails/nomad"
				c.AllowedDatasets = []string{"zroot/jails/base"}
			},
			wantErr: "allowed_datasets",
		},
		{
			name: "allowed_datasets is not a string prefix match",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/jails/base-evil@ready"
			},
			driver: func(c *Config) {
				c.ZFSParent = "zroot/jails/nomad"
				c.AllowedDatasets = []string{"zroot/jails/base"}
			},
			wantErr: "allowed_datasets",
		},
		{
			name: "zfs_clone of a child of an allowed dataset",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "zroot/jails/base/14.3@ready"
			},
			driver: func(c *Config) {
				c.ZFSParent = "zroot/jails/nomad"
				c.AllowedDatasets = []string{"zroot/jails/base"}
			},
		},
		{
			name: "zfs_clone that zfs(8) would read as an option",
			mutate: func(tc *TaskConfig) {
				tc.Path = ""
				tc.ZFSClone = "-omountpoint=/etc@x"
			},
			driver: func(c *Config) {
				c.ZFSParent = "zroot/jails/nomad"
				c.AllowPrivileged = true
			},
			wantErr: "not a snapshot",
		},
		{
			name:    "path with no allowed_paths",
			driver:  func(c *Config) { c.AllowedPaths = nil },
			wantErr: "sets no allowed_paths",
		},
		{
			name: "path with no allowed_paths, where job authors are trusted",
			driver: func(c *Config) {
				c.AllowedPaths = nil
				c.AllowPrivileged = true
			},
		},
		{
			name:    "addresses without alias mode",
			mutate:  func(tc *TaskConfig) { tc.IP4Addr = []string{"10.0.0.5"} },
			wantErr: "network_mode",
		},
		{
			name: "alias mode needs an address",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkAlias
			},
			wantErr: "at least one ip4_addr",
		},
		{
			name: "alias address with an interface",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkAlias
				tc.IP4Addr = []string{"em0|10.0.0.5/24"}
			},
		},
		{
			name: "alias address that is not an address",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkAlias
				tc.IP4Addr = []string{"em0|not-an-address"}
			},
			wantErr: "not an IP address",
		},
		{
			name: "vnet without a bridge",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
			},
			wantErr: "needs a bridge",
		},
		{
			name: "vnet with the operator's bridge",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
			},
			driver: func(c *Config) { c.Bridge = "nomadbr0" },
		},
		{
			name: "vnet with its own bridge and address",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
				tc.Vnet = &VnetConfig{
					Bridge:  "bridge0",
					Address: "10.88.0.5/24",
					Gateway: "10.88.0.1",
				}
			},
		},
		{
			name: "vnet address without a prefix length",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
				tc.Vnet = &VnetConfig{Bridge: "bridge0", Address: "10.88.0.5"}
			},
			wantErr: "prefix length",
		},
		{
			name: "vnet gateway without an address",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
				tc.Vnet = &VnetConfig{Bridge: "bridge0", Gateway: "10.88.0.1"}
			},
			wantErr: "gateway needs address",
		},
		{
			name: "vnet address of the wrong family",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
				tc.Vnet = &VnetConfig{Bridge: "bridge0", Address: "2001:db8::5/64"}
			},
			wantErr: "not an IPv4",
		},
		{
			name: "vnet with IPv6 only",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
				tc.Vnet = &VnetConfig{
					Bridge:   "bridge0",
					Address6: "2001:db8::5/64",
					Gateway6: "2001:db8::1",
				}
			},
		},
		{
			name: "vnet with a multicast MAC",
			mutate: func(tc *TaskConfig) {
				tc.NetworkMode = NetworkVnet
				tc.Vnet = &VnetConfig{Bridge: "bridge0", MAC: "01:00:5e:00:00:01"}
			},
			wantErr: "group bit",
		},
		{
			name: "vnet block in inherit mode",
			mutate: func(tc *TaskConfig) {
				tc.Vnet = &VnetConfig{Bridge: "bridge0"}
			},
			wantErr: "vnet block needs network_mode",
		},
		{
			name:    "devfs ruleset without devfs",
			mutate:  func(tc *TaskConfig) { tc.MountDevfs = false; tc.DevfsRuleset = 4 },
			wantErr: "mount_devfs is false",
		},
		{
			name:    "a task choosing its own devfs ruleset",
			mutate:  func(tc *TaskConfig) { tc.DevfsRuleset = 5 },
			wantErr: "devfs_ruleset needs allow_privileged",
		},
		{
			name:   "a task choosing its own devfs ruleset, where job authors are trusted",
			mutate: func(tc *TaskConfig) { tc.DevfsRuleset = 5 },
			driver: func(c *Config) { c.AllowPrivileged = true },
		},
		{
			name:    "enforce_statfs out of range",
			mutate:  func(tc *TaskConfig) { tc.EnforceStatfs = 3 },
			wantErr: "enforce_statfs",
		},
		{
			name:    "securelevel out of range",
			mutate:  func(tc *TaskConfig) { tc.Securelevel = 4 },
			wantErr: "securelevel",
		},
		{
			name:    "allow needs allow_privileged",
			mutate:  func(tc *TaskConfig) { tc.Allow = []string{"mount"} },
			wantErr: "allow_privileged",
		},
		{
			name:   "allow with allow_privileged",
			mutate: func(tc *TaskConfig) { tc.Allow = []string{"mount", "mount.zfs"} },
			driver: func(c *Config) { c.AllowPrivileged = true },
		},
		{
			name:    "allow entries are unprefixed",
			mutate:  func(tc *TaskConfig) { tc.Allow = []string{"allow.mount"} },
			driver:  func(c *Config) { c.AllowPrivileged = true },
			wantErr: `write "mount"`,
		},
		{
			name:   "memory_hard_limit needs no privilege",
			mutate: func(tc *TaskConfig) { tc.MemoryHardLimit = true },
		},
		{
			name: "memory_hard_limit without the task's limits",
			mutate: func(tc *TaskConfig) {
				tc.MemoryHardLimit = true
				tc.ResourceLimits = false
			},
			wantErr: "memory_hard_limit needs",
		},
		{
			name:    "memory_hard_limit on a node that applies no rules",
			mutate:  func(tc *TaskConfig) { tc.MemoryHardLimit = true },
			driver:  func(c *Config) { c.ResourceLimits = false },
			wantErr: "memory_hard_limit needs",
		},
		{
			name:   "extra_rctl on a node that applies no rules",
			mutate: func(tc *TaskConfig) { tc.ExtraRCTL = []string{"maxproc:deny=50"} },
			driver: func(c *Config) {
				c.AllowPrivileged = true
				c.ResourceLimits = false
			},
			wantErr: "resource_limits = false",
		},
		{
			name: "extra_rctl without the task's derived limits",
			mutate: func(tc *TaskConfig) {
				tc.ResourceLimits = false
				tc.ExtraRCTL = []string{"maxproc:deny=50"}
			},
			driver: func(c *Config) { c.AllowPrivileged = true },
		},
		{
			name:    "jail_params needs allow_privileged",
			mutate:  func(tc *TaskConfig) { tc.JailParams = mapList{{"osrelease": "14.2-RELEASE"}} },
			wantErr: "allow_privileged",
		},
		{
			name:    "jail_params may not set what the driver sets",
			mutate:  func(tc *TaskConfig) { tc.JailParams = mapList{{"path": "/etc"}} },
			driver:  func(c *Config) { c.AllowPrivileged = true },
			wantErr: "set by the driver",
		},
		{
			name: "mount without a source",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Target: "/usr/ports", Type: "nullfs"}}
			},
			wantErr: "source is required",
		},
		{
			name: "mount over the jail root",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Source: "/tmp", Target: "/", Type: "nullfs"}}
			},
			wantErr: "jail root",
		},
		{
			name: "host mount with no allowed_mounts",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Source: "/etc", Target: "/host-etc"}}
			},
			wantErr: "sets no allowed_mounts",
		},
		{
			name: "host mount with allowed_mounts",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Source: "/data/www", Target: "/data"}}
			},
			driver: func(c *Config) { c.AllowedMounts = []string{"/data"} },
		},
		{
			name: "a second devfs",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Target: "/dev2", Type: "devfs"}}
			},
			driver:  func(c *Config) { c.AllowPrivileged = true },
			wantErr: "mounted by the driver",
		},
		{
			name: "an option that would name another source",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{
					Source: "/data/www", Target: "/data",
					Options: mapList{{"target": "/"}},
				}}
			},
			driver: func(c *Config) {
				c.AllowedMounts = []string{"/data"}
				c.AllowPrivileged = true
			},
			wantErr: `"target" is set by the driver`,
		},
		{
			name: "sizing a tmpfs",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{
					Target: "/tmp", Type: "tmpfs",
					Options: mapList{{"size": "64m", "mode": "1777"}},
				}}
			},
		},
		{
			name: "any other mount option",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{
					Target: "/tmp", Type: "tmpfs",
					Options: mapList{{"nosymfollow": ""}},
				}}
			},
			wantErr: "needs allow_privileged",
		},
		{
			name: "any other mount option, where job authors are trusted",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{
					Target: "/tmp", Type: "tmpfs",
					Options: mapList{{"nosymfollow": ""}},
				}}
			},
			driver: func(c *Config) { c.AllowPrivileged = true },
		},
		{
			name: "mount of an unsupported filesystem",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Target: "/mnt", Type: "nfs"}}
			},
			wantErr: "not a filesystem this driver mounts",
		},
		{
			name: "mount with a relative target",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Source: "/tmp", Target: "mnt"}}
			},
			wantErr: "absolute path",
		},
		{
			name:    "seeing the host's mount table",
			mutate:  func(tc *TaskConfig) { tc.EnforceStatfs = 1 },
			wantErr: "needs allow_privileged",
		},
		{
			name:   "seeing the host's mount table, where job authors are trusted",
			mutate: func(tc *TaskConfig) { tc.EnforceStatfs = 0 },
			driver: func(c *Config) { c.AllowPrivileged = true },
		},
		{
			name: "valid tmpfs mount",
			mutate: func(tc *TaskConfig) {
				tc.Mounts = []MountConfig{{Target: "/tmp", Type: "tmpfs"}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfig()
			if tc.driver != nil {
				tc.driver(cfg)
			}
			task := defaultTaskConfig()
			if tc.mutate != nil {
				tc.mutate(task)
			}
			checkErr(t, task.Validate(cfg), tc.wantErr)
		})
	}
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("unexpected error: %v", err)
	case want == "":
		return
	case err == nil:
		t.Fatalf("expected an error containing %q, got none", want)
	case !strings.Contains(err.Error(), want):
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func TestPathWithin(t *testing.T) {
	tests := []struct {
		path, root string
		want       bool
	}{
		{"/jails/a", "/jails", true},
		{"/jails", "/jails", true},
		{"/jails2/a", "/jails", false},
		{"/jailsx", "/jails", false},
		{"/anything", "/", true},
		{"/jails/a/b", "/jails/a", true},
	}
	for _, tc := range tests {
		if got := pathWithin(tc.path, tc.root); got != tc.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", tc.path, tc.root, got, tc.want)
		}
	}
}

// TestPathAllowed uses real directories, since the boundary is drawn on real
// paths: a symbolic link must not cross it from either side.
func TestPathAllowed(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"jails/www", "jails-evil/www", "elsewhere"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) string {
		t.Helper()
		path := filepath.Join(base, name)
		if err := os.Symlink(filepath.Join(base, target), path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	escape := link("elsewhere", "jails/escape")
	alias := link("jails", "alias")

	jails := filepath.Join(base, "jails")
	tests := []struct {
		name    string
		path    string
		allowed []string
		trusted bool
		wantErr string
	}{
		{name: "inside", path: filepath.Join(jails, "www"), allowed: []string{jails}},
		{name: "the directory itself", path: jails, allowed: []string{jails}},
		{name: "outside", path: filepath.Join(base, "elsewhere"), allowed: []string{jails}, wantErr: "is not under"},
		{
			name: "a sibling that shares the prefix",
			path: filepath.Join(base, "jails-evil/www"), allowed: []string{jails}, wantErr: "is not under",
		},
		{
			name: "a link inside that leads outside",
			path: escape, allowed: []string{jails}, wantErr: "is not under",
		},
		{
			name: "an allowed directory named through a link",
			path: filepath.Join(jails, "www"), allowed: []string{alias},
		},
		{
			name: "a path named through a link to an allowed directory",
			path: filepath.Join(alias, "www"), allowed: []string{jails},
		},
		{name: "no list", path: filepath.Join(jails, "www"), wantErr: "sets no allowed_paths"},
		{name: "no list, job authors trusted", path: filepath.Join(base, "elsewhere"), trusted: true},
		{
			name: "a list still binds a trusted job",
			path: filepath.Join(base, "elsewhere"), allowed: []string{jails}, trusted: true,
			wantErr: "is not under",
		},
		{
			name: "a path that does not exist",
			path: filepath.Join(jails, "nope"), allowed: []string{jails}, wantErr: "no such file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{AllowPrivileged: tc.trusted}
			checkErr(t, cfg.pathAllowed("allowed_paths", tc.path, tc.allowed), tc.wantErr)
		})
	}
}

func TestValidDatasetName(t *testing.T) {
	ok := []string{"zroot", "zroot/jails", "zroot/jails/base-14.3", "tank/a_b:c.d"}
	bad := []string{
		"", "/zroot", "zroot/", "zroot//jails", "-o", "-omountpoint=/etc", "zroot/jails@snap",
		"zroot/ja ils", "9pool", "zroot/jails;reboot", "zroot/$(reboot)",
	}
	for _, s := range ok {
		if !validDatasetName(s) {
			t.Errorf("validDatasetName(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validDatasetName(s) {
			t.Errorf("validDatasetName(%q) = true, want false", s)
		}
	}
}

func TestSnapshotDataset(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"zroot/jails/base@ready", "zroot/jails/base", true},
		{"zroot@a", "zroot", true},
		{"zroot/jails/base", "", false},
		{"zroot/jails/base@", "", false},
		{"@ready", "", false},
		{"zroot/jails/base@a@b", "", false},
		{"zroot/jails/base@a/b", "", false},
		{"-omountpoint=/etc@x", "", false},
	}
	for _, tc := range tests {
		got, ok := snapshotDataset(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("snapshotDataset(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestTaskConfigRejectsHostRoot(t *testing.T) {
	tc := defaultTaskConfig()
	tc.Path = "/"
	err := tc.Validate(defaultConfig())
	checkErr(t, err, "host's root")
}

func TestReservedJailParamsPointAtTheRightField(t *testing.T) {
	cfg := defaultConfig()
	cfg.AllowPrivileged = true

	// Every parameter the driver derives has to be refused, and one with a
	// task field of its own has to say which.
	for name, field := range reservedJailParams {
		tc := defaultTaskConfig()
		tc.JailParams = mapList{{name: "x"}}
		err := tc.Validate(cfg)
		if err == nil {
			t.Errorf("jail_params %q was accepted", name)
			continue
		}
		if field != "" && !strings.Contains(err.Error(), field) {
			t.Errorf("the error for %q does not mention %q: %v", name, field, err)
		}
	}
}

// TestReservedJailParamsCoverTheDerivedOnes keeps the reserved list and what
// jailParams sets from drifting apart.
func TestReservedJailParamsCoverTheDerivedOnes(t *testing.T) {
	for _, name := range []string{
		"name", "path", "persist", "host.hostname", "enforce_statfs",
		"children.max", "securelevel", "devfs_ruleset",
		"vnet", "ip4", "ip6", "ip4.addr", "ip6.addr",
	} {
		if _, ok := reservedJailParams[name]; !ok {
			t.Errorf("%q is derived by the driver but is not reserved", name)
		}
	}
}
