// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
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

func defaultConfig() *Config {
	return &Config{
		Enabled:            true,
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
			driver: func(c *Config) { c.ZFSParent = "zroot/jails/nomad" },
		},
		{
			name:    "path outside allowed_paths",
			driver:  func(c *Config) { c.AllowedPaths = []string{"/zroot/jails"} },
			wantErr: "allowed_paths",
		},
		{
			name:   "path inside allowed_paths",
			mutate: func(tc *TaskConfig) { tc.Path = "/zroot/jails/www" },
			driver: func(c *Config) { c.AllowedPaths = []string{"/zroot/jails"} },
		},
		{
			name:    "allowed_paths is not a string prefix match",
			mutate:  func(tc *TaskConfig) { tc.Path = "/zroot/jails-evil/www" },
			driver:  func(c *Config) { c.AllowedPaths = []string{"/zroot/jails"} },
			wantErr: "allowed_paths",
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
			name:    "jail_params needs allow_privileged",
			mutate:  func(tc *TaskConfig) { tc.JailParams = map[string]string{"osrelease": "14.2-RELEASE"} },
			wantErr: "allow_privileged",
		},
		{
			name:    "jail_params may not set what the driver sets",
			mutate:  func(tc *TaskConfig) { tc.JailParams = map[string]string{"path": "/etc"} },
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

func TestCheckAllowedPathEmptyListAllowsAnything(t *testing.T) {
	if err := checkAllowedPath("/anywhere/at/all", nil); err != nil {
		t.Errorf("an empty allowed_paths should allow anything, got %v", err)
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
		tc.JailParams = map[string]string{name: "x"}
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
