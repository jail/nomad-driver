// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

// Network modes, after the ways jail(8) can handle a jail's network stack.
const (
	// NetworkInherit shares the host's stack and addresses (ip4=inherit,
	// ip6=inherit), so the ports Nomad allocated on the host reach the
	// task.  It is the default.
	NetworkInherit = "inherit"

	// NetworkAlias restricts the jail to addresses configured on host
	// interfaces (ip4.addr, ip6.addr).
	NetworkAlias = "alias"

	// NetworkVnet gives the jail a stack of its own (vnet=new) and an
	// epair(4) leg bridged to the host.
	NetworkVnet = "vnet"

	// NetworkNone disables IPv4 and IPv6 in the jail (ip4=disable,
	// ip6=disable).
	NetworkNone = "none"
)

// devfs rulesets from /etc/defaults/devfs.rules.  A jail must never get ruleset
// 0, which hides nothing.
const (
	devfsRulesetJail     = 4 // devfsrules_jail
	devfsRulesetJailVnet = 5 // devfsrules_jail_vnet
)

// configSpec is the schema of the plugin stanza in the client's configuration.
// These are the operator's settings, and draw the driver's security boundaries.
var configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
	"enabled": hclspec.NewDefault(
		hclspec.NewAttr("enabled", "bool", false),
		hclspec.NewLiteral("true"),
	),

	// Confines a job's choice of jail root.  Unset allows any.
	"allowed_paths": hclspec.NewAttr("allowed_paths", "list(string)", false),

	// Gates the settings that can give a task privileges over the host:
	// allow, jail_params and extra_rctl.
	"allow_privileged": hclspec.NewDefault(
		hclspec.NewAttr("allow_privileged", "bool", false),
		hclspec.NewLiteral("false"),
	),

	"default_network_mode": hclspec.NewDefault(
		hclspec.NewAttr("default_network_mode", "string", false),
		hclspec.NewLiteral(`"inherit"`),
	),

	// Default bridge for vnet tasks.
	"bridge": hclspec.NewAttr("bridge", "string", false),

	// Parent dataset for per-task ZFS clones.
	"zfs_parent": hclspec.NewAttr("zfs_parent", "string", false),

	"devfs_ruleset": hclspec.NewAttr("devfs_ruleset", "number", false),

	"resource_limits": hclspec.NewDefault(
		hclspec.NewAttr("resource_limits", "bool", false),
		hclspec.NewLiteral("true"),
	),

	// Reap jails left behind by a previous agent at startup.
	"gc": hclspec.NewDefault(hclspec.NewBlock("gc", false, hclspec.NewObject(map[string]*hclspec.Spec{
		"jail": hclspec.NewDefault(
			hclspec.NewAttr("jail", "bool", false),
			hclspec.NewLiteral("true"),
		),
	})), hclspec.NewLiteral(`{ jail = true }`)),
})

// taskConfigSpec is the schema of a task's config stanza.  No setting in it may
// be a map(string); see mapList.
var taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
	"command":  hclspec.NewAttr("command", "string", true),
	"args":     hclspec.NewAttr("args", "list(string)", false),
	"work_dir": hclspec.NewAttr("work_dir", "string", false),

	"path":      hclspec.NewAttr("path", "string", false),
	"zfs_clone": hclspec.NewAttr("zfs_clone", "string", false),
	"readonly_rootfs": hclspec.NewDefault(
		hclspec.NewAttr("readonly_rootfs", "bool", false),
		hclspec.NewLiteral("false"),
	),

	"hostname": hclspec.NewAttr("hostname", "string", false),

	"network_mode": hclspec.NewAttr("network_mode", "string", false),
	"ip4_addr":     hclspec.NewAttr("ip4_addr", "list(string)", false),
	"ip6_addr":     hclspec.NewAttr("ip6_addr", "list(string)", false),
	"vnet": hclspec.NewBlock("vnet", false, hclspec.NewObject(map[string]*hclspec.Spec{
		"bridge":   hclspec.NewAttr("bridge", "string", false),
		"address":  hclspec.NewAttr("address", "string", false),
		"gateway":  hclspec.NewAttr("gateway", "string", false),
		"address6": hclspec.NewAttr("address6", "string", false),
		"gateway6": hclspec.NewAttr("gateway6", "string", false),
		"mac":      hclspec.NewAttr("mac", "string", false),
		"mtu":      hclspec.NewAttr("mtu", "number", false),
	})),

	"mount_devfs": hclspec.NewDefault(
		hclspec.NewAttr("mount_devfs", "bool", false),
		hclspec.NewLiteral("true"),
	),
	"devfs_ruleset": hclspec.NewAttr("devfs_ruleset", "number", false),
	"mount_fdescfs": hclspec.NewDefault(
		hclspec.NewAttr("mount_fdescfs", "bool", false),
		hclspec.NewLiteral("false"),
	),
	"mount_procfs": hclspec.NewDefault(
		hclspec.NewAttr("mount_procfs", "bool", false),
		hclspec.NewLiteral("false"),
	),
	"mount": hclspec.NewBlockList("mount", hclspec.NewObject(map[string]*hclspec.Spec{
		"source": hclspec.NewAttr("source", "string", false),
		"target": hclspec.NewAttr("target", "string", true),
		"type": hclspec.NewDefault(
			hclspec.NewAttr("type", "string", false),
			hclspec.NewLiteral(`"nullfs"`),
		),
		"readonly": hclspec.NewDefault(
			hclspec.NewAttr("readonly", "bool", false),
			hclspec.NewLiteral("false"),
		),
		"options": hclspec.NewAttr("options", "list(map(string))", false),
	})),

	"allow": hclspec.NewAttr("allow", "list(string)", false),
	// -1 is the kernel's "no restriction", and what a jail gets if the
	// parameter is not set.
	"securelevel": hclspec.NewDefault(
		hclspec.NewAttr("securelevel", "number", false),
		hclspec.NewLiteral("-1"),
	),
	// The kernel's defaults: the jail sees only its own filesystems and may
	// hold no jails.
	"enforce_statfs": hclspec.NewDefault(
		hclspec.NewAttr("enforce_statfs", "number", false),
		hclspec.NewLiteral("2"),
	),
	"children_max": hclspec.NewDefault(
		hclspec.NewAttr("children_max", "number", false),
		hclspec.NewLiteral("0"),
	),
	"jail_params": hclspec.NewAttr("jail_params", "list(map(string))", false),

	"resource_limits": hclspec.NewDefault(
		hclspec.NewAttr("resource_limits", "bool", false),
		hclspec.NewLiteral("true"),
	),
	"extra_rctl": hclspec.NewAttr("extra_rctl", "list(string)", false),
	"cpuset": hclspec.NewDefault(
		hclspec.NewAttr("cpuset", "bool", false),
		hclspec.NewLiteral("true"),
	),
})

// Config is the decoded form of configSpec.
type Config struct {
	Enabled            bool     `codec:"enabled"`
	AllowedPaths       []string `codec:"allowed_paths"`
	AllowPrivileged    bool     `codec:"allow_privileged"`
	DefaultNetworkMode string   `codec:"default_network_mode"`
	Bridge             string   `codec:"bridge"`
	ZFSParent          string   `codec:"zfs_parent"`
	DevfsRuleset       int      `codec:"devfs_ruleset"`
	ResourceLimits     bool     `codec:"resource_limits"`
	GC                 GCConfig `codec:"gc"`
}

// GCConfig controls what the driver reclaims when it starts.
type GCConfig struct {
	Jail bool `codec:"jail"`
}

// TaskConfig is the decoded form of taskConfigSpec.
type TaskConfig struct {
	Command string   `codec:"command"`
	Args    []string `codec:"args"`
	WorkDir string   `codec:"work_dir"`

	Path           string `codec:"path"`
	ZFSClone       string `codec:"zfs_clone"`
	ReadonlyRootfs bool   `codec:"readonly_rootfs"`

	Hostname string `codec:"hostname"`

	NetworkMode string      `codec:"network_mode"`
	IP4Addr     []string    `codec:"ip4_addr"`
	IP6Addr     []string    `codec:"ip6_addr"`
	Vnet        *VnetConfig `codec:"vnet"`

	MountDevfs   bool          `codec:"mount_devfs"`
	DevfsRuleset int           `codec:"devfs_ruleset"`
	MountFdescfs bool          `codec:"mount_fdescfs"`
	MountProcfs  bool          `codec:"mount_procfs"`
	Mounts       []MountConfig `codec:"mount"`

	Allow []string `codec:"allow"`
	// Securelevel is -1 if the task did not ask for one.
	Securelevel   int     `codec:"securelevel"`
	EnforceStatfs int     `codec:"enforce_statfs"`
	ChildrenMax   int     `codec:"children_max"`
	JailParams    mapList `codec:"jail_params"`

	ResourceLimits bool     `codec:"resource_limits"`
	ExtraRCTL      []string `codec:"extra_rctl"`
	Cpuset         bool     `codec:"cpuset"`
}

// VnetConfig describes a vnet task's epair(4) leg.  With no Address the
// interface is brought up and left for the task to configure.
type VnetConfig struct {
	Bridge   string `codec:"bridge"`
	Address  string `codec:"address"`
	Gateway  string `codec:"gateway"`
	Address6 string `codec:"address6"`
	Gateway6 string `codec:"gateway6"`
	MAC      string `codec:"mac"`
	MTU      int    `codec:"mtu"`
}

// MountConfig is an extra filesystem to mount in the jail.
type MountConfig struct {
	Source   string  `codec:"source"`
	Target   string  `codec:"target"`
	Type     string  `codec:"type"`
	Readonly bool    `codec:"readonly"`
	Options  mapList `codec:"options"`
}

// mapList is a map of strings as a task's configuration delivers one.
//
// Nomad hands a driver an HCL object as a list of objects, so a setting
// declared map(string) fails validation for every job that sets it.  It has to
// be declared list(map(string)) and the entries merged, a later one winning.
type mapList []map[string]string

func (l mapList) merged() map[string]string {
	out := map[string]string{}
	for _, m := range l {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// Validate checks a plugin configuration without touching the system.
func (c *Config) Validate() error {
	switch c.DefaultNetworkMode {
	case NetworkInherit, NetworkAlias, NetworkVnet, NetworkNone:
	default:
		return fmt.Errorf("default_network_mode: %w", badNetworkMode(c.DefaultNetworkMode))
	}
	for _, p := range c.AllowedPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("allowed_paths: %q is not an absolute path", p)
		}
	}
	if c.DevfsRuleset < 0 {
		return fmt.Errorf("devfs_ruleset: %d is negative", c.DevfsRuleset)
	}
	if c.ZFSParent != "" && strings.HasPrefix(c.ZFSParent, "/") {
		return fmt.Errorf("zfs_parent: %q looks like a path, want a dataset name", c.ZFSParent)
	}
	return nil
}

func badNetworkMode(mode string) error {
	return fmt.Errorf("%q is not one of %s, %s, %s, %s",
		mode, NetworkInherit, NetworkAlias, NetworkVnet, NetworkNone)
}

// Validate checks a task configuration against the driver's without touching
// the system, so that a bad job is rejected before anything is created.
func (tc *TaskConfig) Validate(cfg *Config) error {
	if strings.TrimSpace(tc.Command) == "" {
		return fmt.Errorf("command is required")
	}
	if !filepath.IsAbs(tc.Command) {
		// A relative path would depend on a PATH and a working
		// directory the job did not set.
		return fmt.Errorf("command: %q must be an absolute path inside the jail", tc.Command)
	}
	if tc.WorkDir != "" && !filepath.IsAbs(tc.WorkDir) {
		return fmt.Errorf("work_dir: %q must be an absolute path inside the jail", tc.WorkDir)
	}

	switch {
	case tc.Path == "" && tc.ZFSClone == "":
		return fmt.Errorf("one of path or zfs_clone is required")
	case tc.Path != "" && tc.ZFSClone != "":
		return fmt.Errorf("path and zfs_clone are mutually exclusive")
	case tc.Path != "" && !filepath.IsAbs(tc.Path):
		return fmt.Errorf("path: %q is not an absolute path", tc.Path)
	case tc.Path != "" && filepath.Clean(tc.Path) == "/":
		// Tearing down a jail rooted at / would unmount the host.
		return fmt.Errorf("path: may not be the host's root directory")
	}
	if tc.ZFSClone != "" {
		if !strings.Contains(tc.ZFSClone, "@") {
			return fmt.Errorf("zfs_clone: %q is not a snapshot (want dataset@snapshot)", tc.ZFSClone)
		}
		if cfg.ZFSParent == "" {
			return fmt.Errorf("zfs_clone needs zfs_parent set in the driver's plugin configuration")
		}
	}
	if tc.Path != "" {
		if err := checkAllowedPath(tc.Path, cfg.AllowedPaths); err != nil {
			return err
		}
	}

	mode := tc.NetworkMode
	if mode == "" {
		mode = cfg.DefaultNetworkMode
	}
	switch mode {
	case NetworkInherit, NetworkNone:
		if len(tc.IP4Addr) > 0 || len(tc.IP6Addr) > 0 {
			return fmt.Errorf("ip4_addr and ip6_addr need network_mode = %q", NetworkAlias)
		}
		if tc.Vnet != nil {
			return fmt.Errorf("the vnet block needs network_mode = %q", NetworkVnet)
		}
	case NetworkAlias:
		if len(tc.IP4Addr) == 0 && len(tc.IP6Addr) == 0 {
			return fmt.Errorf("network_mode = %q needs at least one ip4_addr or ip6_addr", NetworkAlias)
		}
		if tc.Vnet != nil {
			return fmt.Errorf("the vnet block needs network_mode = %q", NetworkVnet)
		}
		for _, a := range append(append([]string{}, tc.IP4Addr...), tc.IP6Addr...) {
			if err := validateAliasAddr(a); err != nil {
				return err
			}
		}
	case NetworkVnet:
		if len(tc.IP4Addr) > 0 || len(tc.IP6Addr) > 0 {
			return fmt.Errorf("ip4_addr and ip6_addr need network_mode = %q; use the vnet block instead", NetworkAlias)
		}
		if err := tc.Vnet.validate(cfg); err != nil {
			return err
		}
	default:
		return fmt.Errorf("network_mode: %w", badNetworkMode(mode))
	}

	if tc.DevfsRuleset < 0 {
		return fmt.Errorf("devfs_ruleset: %d is negative", tc.DevfsRuleset)
	}
	if tc.DevfsRuleset != 0 && !tc.MountDevfs {
		return fmt.Errorf("devfs_ruleset is set but mount_devfs is false")
	}
	for i, m := range tc.Mounts {
		if err := m.validate(); err != nil {
			return fmt.Errorf("mount[%d]: %w", i, err)
		}
	}

	if tc.EnforceStatfs < 0 || tc.EnforceStatfs > 2 {
		return fmt.Errorf("enforce_statfs: %d is not 0, 1 or 2", tc.EnforceStatfs)
	}
	if tc.Securelevel < -1 || tc.Securelevel > 3 {
		return fmt.Errorf("securelevel: %d is not between -1 and 3", tc.Securelevel)
	}
	if tc.ChildrenMax < 0 {
		return fmt.Errorf("children_max: %d is negative", tc.ChildrenMax)
	}

	if !cfg.AllowPrivileged {
		if len(tc.Allow) > 0 {
			return fmt.Errorf("the allow list needs allow_privileged = true in the driver's plugin configuration")
		}
		if len(tc.JailParams.merged()) > 0 {
			return fmt.Errorf("jail_params needs allow_privileged = true in the driver's plugin configuration")
		}
		if len(tc.ExtraRCTL) > 0 {
			return fmt.Errorf("extra_rctl needs allow_privileged = true in the driver's plugin configuration")
		}
	}
	for _, a := range tc.Allow {
		if strings.HasPrefix(a, "allow.") {
			return fmt.Errorf("allow: write %q, not %q", strings.TrimPrefix(a, "allow."), a)
		}
		if a == "" {
			return fmt.Errorf("allow: empty entry")
		}
	}
	// A job must not reset what the driver derives, or the driver's state
	// would stop describing the jail.
	for name := range tc.JailParams.merged() {
		field, reserved := reservedJailParams[name]
		switch {
		case reserved && field != "":
			return fmt.Errorf("jail_params: %q is set by the driver; use %s instead", name, field)
		case reserved:
			return fmt.Errorf("jail_params: %q is set by the driver", name)
		}
	}

	return nil
}

// reservedJailParams are the parameters the driver sets itself.  Each maps to
// the task setting to use instead, or "" if it is not a job's to set.
var reservedJailParams = map[string]string{
	"jid":            "",
	"name":           "",
	"path":           "path or zfs_clone",
	"persist":        "",
	"lastjid":        "",
	"errmsg":         "",
	"dying":          "",
	"desc":           "",
	"vnet":           "network_mode",
	"ip4":            "network_mode",
	"ip6":            "network_mode",
	"ip4.addr":       "ip4_addr",
	"ip6.addr":       "ip6_addr",
	"host.hostname":  "hostname",
	"enforce_statfs": "enforce_statfs",
	"children.max":   "children_max",
	"securelevel":    "securelevel",
	"devfs_ruleset":  "devfs_ruleset",
}

func (v *VnetConfig) validate(cfg *Config) error {
	bridge := cfg.Bridge
	if v != nil && v.Bridge != "" {
		bridge = v.Bridge
	}
	if bridge == "" {
		return fmt.Errorf("network_mode = %q needs a bridge, from the vnet block or the driver's plugin configuration",
			NetworkVnet)
	}
	if !validInterfaceName(bridge) {
		return fmt.Errorf("vnet: %q is not a valid interface name", bridge)
	}
	if v == nil {
		return nil
	}

	for _, f := range []struct {
		name, value string
		v6          bool
	}{
		{"address", v.Address, false},
		{"address6", v.Address6, true},
	} {
		if f.value == "" {
			continue
		}
		if err := validateCIDR(f.value, f.v6); err != nil {
			return fmt.Errorf("vnet %s: %w", f.name, err)
		}
	}
	for _, f := range []struct {
		name, value string
		v6          bool
	}{
		{"gateway", v.Gateway, false},
		{"gateway6", v.Gateway6, true},
	} {
		if f.value == "" {
			continue
		}
		if err := validateIP(f.value, f.v6); err != nil {
			return fmt.Errorf("vnet %s: %w", f.name, err)
		}
	}
	if v.Gateway != "" && v.Address == "" {
		return fmt.Errorf("vnet gateway needs address")
	}
	if v.Gateway6 != "" && v.Address6 == "" {
		return fmt.Errorf("vnet gateway6 needs address6")
	}
	if v.MAC != "" {
		if err := validateMAC(v.MAC); err != nil {
			return fmt.Errorf("vnet mac: %w", err)
		}
	}
	if v.MTU != 0 && (v.MTU < 72 || v.MTU > 65535) {
		return fmt.Errorf("vnet mtu: %d is out of range", v.MTU)
	}
	return nil
}

func (m *MountConfig) validate() error {
	if !filepath.IsAbs(m.Target) {
		return fmt.Errorf("target: %q must be an absolute path inside the jail", m.Target)
	}
	if filepath.Clean(m.Target) == "/" {
		return fmt.Errorf("target: may not be the jail root")
	}
	switch m.Type {
	case "", "nullfs":
		if m.Source == "" {
			return fmt.Errorf("source is required for a nullfs mount")
		}
		if !filepath.IsAbs(m.Source) {
			return fmt.Errorf("source: %q is not an absolute path on the host", m.Source)
		}
	case "devfs", "fdescfs", "procfs", "linprocfs", "linsysfs", "tmpfs":
		if m.Source != "" {
			return fmt.Errorf("source is not used by a %s mount", m.Type)
		}
	default:
		return fmt.Errorf("type: %q is not a filesystem this driver mounts", m.Type)
	}
	return nil
}

// checkAllowedPath confines a job's jail root to the directories the operator
// listed.  An empty list allows any.
func checkAllowedPath(path string, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	clean := filepath.Clean(path)
	for _, a := range allowed {
		if pathWithin(clean, filepath.Clean(a)) {
			return nil
		}
	}
	return fmt.Errorf("path: %q is not under any of the driver's allowed_paths %v", path, allowed)
}

// pathWithin reports whether path is root or below it, by whole components:
// "/jails2" is not under "/jails".
func pathWithin(path, root string) bool {
	if path == root {
		return true
	}
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}
