// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"fmt"
	"os"
	"runtime"

	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/structs"
	"github.com/jail/nomad-driver/jail"
)

// Node attributes, for jobs to constrain on.
const (
	attrVersion        = "driver.jail.version"
	attrVnet           = "driver.jail.vnet"
	attrZFS            = "driver.jail.zfs"
	attrRCTL           = "driver.jail.rctl"
	attrNested         = "driver.jail.nested"
	attrJexecWorkDir   = "driver.jail.jexec_workdir"
	attrBridge         = "driver.jail.bridge"
	attrAllowPrivilege = "driver.jail.allow_privileged"
)

// buildFingerprint reports the driver's health and what the node can do.  The
// driver is healthy only where it could start a jail; anything else is
// undetected, with the reason.
func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	fp := &drivers.Fingerprint{
		Attributes:        map[string]*structs.Attribute{},
		Health:            drivers.HealthStateHealthy,
		HealthDescription: drivers.DriverHealthy,
	}

	undetected := func(format string, args ...any) *drivers.Fingerprint {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUndetected,
			HealthDescription: fmt.Sprintf(format, args...),
		}
	}

	if !d.config.Enabled {
		return undetected("the jail driver is disabled in the client configuration")
	}
	if runtime.GOOS != "freebsd" {
		return undetected("the jail driver needs FreeBSD, this is %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return undetected("the jail driver needs to run as root, the agent is uid %d", os.Geteuid())
	}

	// An agent that is itself jailed needs children.max raised to create
	// jails.
	if _, err := jail.List(); err != nil {
		return undetected("jail_get(2) failed: %v", err)
	}
	if jailed, ok := sysctlInt("security.jail.jailed"); ok && jailed != 0 {
		children, _ := sysctlInt("security.jail.children.max")
		if children == 0 {
			return undetected("the agent is itself in a jail whose children.max is 0, " +
				"so it cannot create jails")
		}
	}

	// A ruleset that is not loaded would fail every task, usually because
	// devfs_load_rulesets is off.
	if err := checkDevfsRuleset(d.ctx, d.logger, devfsRuleset(&TaskConfig{}, d.config, NetworkInherit)); err != nil {
		return undetected("%v", err)
	}

	version := sysctlString("kern.osrelease")
	if version == "" {
		version = "unknown"
	}
	fp.Attributes[attrVersion] = structs.NewStringAttribute(version)

	// The vnet parameter exists only with VIMAGE.
	hasVnet := jail.HasParam("vnet")
	fp.Attributes[attrVnet] = structs.NewBoolAttribute(hasVnet)

	// /dev/zfs shows that the ZFS module is loaded.
	_, zfsErr := os.Stat("/dev/zfs")
	fp.Attributes[attrZFS] = structs.NewBoolAttribute(zfsErr == nil)

	// rctl(8) needs RACCT and RCTL in the kernel and racct switched on.
	racct, _ := sysctlInt("kern.racct.enable")
	fp.Attributes[attrRCTL] = structs.NewBoolAttribute(racct != 0)

	nested, _ := sysctlInt("security.jail.jailed")
	fp.Attributes[attrNested] = structs.NewBoolAttribute(nested != 0)

	// Whether work_dir can go to jexec(8) rather than through a shell in
	// the image.
	fp.Attributes[attrJexecWorkDir] = structs.NewBoolAttribute(jexecSupportsWorkDir())

	fp.Attributes[attrAllowPrivilege] = structs.NewBoolAttribute(d.config.AllowPrivileged)
	if d.config.Bridge != "" {
		fp.Attributes[attrBridge] = structs.NewStringAttribute(d.config.Bridge)
	}

	// Every task would fail to start.
	if d.config.DefaultNetworkMode == NetworkVnet && !hasVnet {
		return undetected("default_network_mode is %q but the kernel has no VIMAGE support", NetworkVnet)
	}

	return fp
}
