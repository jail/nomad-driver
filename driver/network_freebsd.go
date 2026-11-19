// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// configureAliases adds the host aliases an alias-mode jail's addresses need.
// An entry that names no interface is taken to be configured already, as
// jail(8) takes it.  It returns the aliases it added, so that a failure part
// way can be undone.
func configureAliases(ctx context.Context, logger hclog.Logger, tc *TaskConfig) ([]string, error) {
	var added []string
	for _, raw := range append(append([]string{}, tc.IP4Addr...), tc.IP6Addr...) {
		spec, err := parseIfaddr(raw)
		if err != nil {
			return added, err
		}
		if spec.Iface == "" {
			continue
		}
		if _, err := run(ctx, logger, pathIfconfig, spec.ifconfigAliasArgs(false)...); err != nil {
			return added, fmt.Errorf("adding alias %s: %w", spec, err)
		}
		added = append(added, spec.String())
	}
	return added, nil
}

// removeAliases removes the aliases configureAliases added, and keeps going
// past a failure.
func removeAliases(ctx context.Context, logger hclog.Logger, aliases []string) error {
	var firstErr error
	for _, raw := range aliases {
		spec, err := parseIfaddr(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := run(ctx, logger, pathIfconfig, spec.ifconfigAliasArgs(true)...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("removing alias %s: %w", spec, err)
		}
	}
	return firstErr
}

// createVnet gives a jail a network stack of its own.
//
// It makes an epair(4), bridges the "a" leg on the host, moves the "b" leg into
// the jail and configures it there; see configureVnetInterface.  The host leg
// is renamed to epairHostName(st.Name) as soon as it exists, so that it can be
// found from the jail's name.  If this fails the caller has to call
// destroyEpair, since the host leg may exist by then.
func createVnet(ctx context.Context, logger hclog.Logger, bridge string, v *VnetConfig, st *jailState) error {
	hostSide := epairHostName(st.Name)

	// An interface of that name is what an earlier run of this task left
	// behind.
	if !interfaceGone(ctx, logger, hostSide) {
		logger.Warn("destroying an epair left behind by an earlier run", "interface", hostSide)
		if _, err := run(ctx, logger, pathIfconfig, hostSide, "destroy"); err != nil {
			return fmt.Errorf("destroying stale %s: %w", hostSide, err)
		}
	}

	// ifconfig prints the name of the "a" leg; the "b" leg differs in the
	// last character.
	out, err := run(ctx, logger, pathIfconfig, "epair", "create")
	if err != nil {
		return fmt.Errorf("creating epair: %w", err)
	}
	created := strings.TrimSpace(out)
	if !strings.HasSuffix(created, "a") {
		return fmt.Errorf("creating epair: expected a name ending in \"a\", got %q", created)
	}
	jailSide := created[:len(created)-1] + "b"

	if _, err := run(ctx, logger, pathIfconfig, created, "name", hostSide); err != nil {
		// Nothing records the name it was created under, so it goes now
		// or never.
		if _, derr := run(ctx, logger, pathIfconfig, created, "destroy"); derr != nil {
			logger.Error("could not destroy an epair that could not be renamed",
				"interface", created, "error", derr)
		}
		return fmt.Errorf("renaming %s to %s: %w", created, hostSide, err)
	}
	st.Epair = hostSide

	// Say whose they are, for whoever reads ifconfig's output.
	for _, leg := range []string{hostSide, jailSide} {
		if _, err := run(ctx, logger, pathIfconfig, leg, "description", "nomad-jail "+st.Name); err != nil {
			logger.Warn("could not set interface description", "interface", leg, "error", err)
		}
	}

	if v != nil && v.MTU != 0 {
		for _, leg := range []string{hostSide, jailSide} {
			if _, err := run(ctx, logger, pathIfconfig, leg, "mtu", strconv.Itoa(v.MTU)); err != nil {
				return fmt.Errorf("setting mtu on %s: %w", leg, err)
			}
		}
	}
	if v != nil && v.MAC != "" {
		// Before the leg moves into the jail, where the host can no
		// longer configure it.
		if _, err := run(ctx, logger, pathIfconfig, jailSide, "ether", v.MAC); err != nil {
			return fmt.Errorf("setting ether address on %s: %w", jailSide, err)
		}
	}

	if _, err := run(ctx, logger, pathIfconfig, bridge, "addm", hostSide); err != nil {
		return fmt.Errorf("adding %s to bridge %s: %w", hostSide, bridge, err)
	}
	st.Bridge = bridge
	if _, err := run(ctx, logger, pathIfconfig, hostSide, "up"); err != nil {
		return fmt.Errorf("bringing up %s: %w", hostSide, err)
	}

	// The jail side is lent, not given: the kernel returns it to the host
	// when the jail's stack goes, and it is destroying the host side that
	// removes the pair.
	if _, err := run(ctx, logger, pathIfconfig, jailSide, "vnet", st.Name); err != nil {
		return fmt.Errorf("moving %s into jail %s: %w", jailSide, st.Name, err)
	}

	return configureVnetInterface(ctx, logger, st.Name, jailSide, v, st)
}

// configureVnetInterface addresses the jail's leg and sets its default routes.
//
// It uses the host's ifconfig(8) and route(8) with -j.  Going through jexec(8)
// would run the image's own /sbin/ifconfig as root, and need the image to have
// one.  With no address the interface is brought up and left for the task to
// configure.
func configureVnetInterface(ctx context.Context, logger hclog.Logger, jailName string, iface string, v *VnetConfig, st *jailState) error {
	inJail := func(tool string, args ...string) error {
		_, err := run(ctx, logger, tool, append([]string{"-j", jailName}, args...)...)
		return err
	}

	if err := configureLoopback(ctx, logger, jailName); err != nil {
		return err
	}
	if err := inJail(pathIfconfig, iface, "up"); err != nil {
		return fmt.Errorf("bringing up %s in the jail: %w", iface, err)
	}
	if v == nil {
		return nil
	}

	if v.Address != "" {
		if err := inJail(pathIfconfig, iface, "inet", v.Address); err != nil {
			return fmt.Errorf("setting %s on %s: %w", v.Address, iface, err)
		}
		ip, _, err := net.ParseCIDR(v.Address)
		if err != nil {
			return fmt.Errorf("vnet address %q: %w", v.Address, err)
		}
		st.IP = ip.String()
	}
	if v.Gateway != "" {
		if err := inJail(pathRoute, "-4", "add", "default", v.Gateway); err != nil {
			return fmt.Errorf("adding default route via %s: %w", v.Gateway, err)
		}
	}

	if v.Address6 != "" {
		if err := inJail(pathIfconfig, iface, "inet6", v.Address6); err != nil {
			return fmt.Errorf("setting %s on %s: %w", v.Address6, iface, err)
		}
		if st.IP == "" {
			ip, _, err := net.ParseCIDR(v.Address6)
			if err != nil {
				return fmt.Errorf("vnet address6 %q: %w", v.Address6, err)
			}
			st.IP = ip.String()
		}
	}
	if v.Gateway6 != "" {
		if err := inJail(pathRoute, "-6", "add", "default", v.Gateway6); err != nil {
			return fmt.Errorf("adding default IPv6 route via %s: %w", v.Gateway6, err)
		}
	}

	return nil
}

// configureLoopback sets up lo0 in a jail with a stack of its own.  A new vnet
// has it down and unaddressed; bringing it up gives it ::1 but not 127.0.0.1,
// which on a host is rc.d/netif's doing.
func configureLoopback(ctx context.Context, logger hclog.Logger, jailName string) error {
	for _, args := range [][]string{
		{"lo0", "up"},
		{"lo0", "inet", "127.0.0.1/8"},
	} {
		args = append([]string{"-j", jailName}, args...)
		if _, err := run(ctx, logger, pathIfconfig, args...); err != nil {
			return fmt.Errorf("configuring lo0 in the jail: %w", err)
		}
	}
	return nil
}

// destroyEpair removes a vnet task's epair(4) by destroying its host leg.
//
// Removing the jail does not: vnet_if_return() hands the jail's leg back to the
// host.  The name is derived rather than read from the state, which may have
// been written before a reboot.
func destroyEpair(ctx context.Context, logger hclog.Logger, st *jailState) error {
	if st.Epair == "" {
		return nil
	}
	hostSide := epairHostName(st.Name)

	// Not required, since destroying an interface detaches it, but it keeps
	// the bridge tidy if the destroy fails.
	if st.Bridge != "" {
		if _, err := run(ctx, logger, pathIfconfig, st.Bridge, "deletem", hostSide); err != nil {
			logger.Trace("could not remove epair from bridge", "epair", hostSide,
				"bridge", st.Bridge, "error", err)
		}
	}
	if _, err := run(ctx, logger, pathIfconfig, hostSide, "destroy"); err != nil {
		// Teardown has to be safe to run twice.
		if interfaceGone(ctx, logger, hostSide) {
			return nil
		}
		return fmt.Errorf("destroying %s: %w", hostSide, err)
	}
	return nil
}

func interfaceGone(ctx context.Context, logger hclog.Logger, iface string) bool {
	_, err := run(ctx, logger, pathIfconfig, iface)
	return err != nil
}

// bridgeFor picks the bridge a vnet task's host leg joins: the task's, else the
// operator's.
func bridgeFor(cfg *Config, v *VnetConfig) string {
	if v != nil && v.Bridge != "" {
		return v.Bridge
	}
	return cfg.Bridge
}
