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
// the jail and configures it there with jexec(8).  If this fails the caller has
// to destroy st.Epair, since the host leg may exist by then.
func createVnet(ctx context.Context, logger hclog.Logger, jid int, bridge string, v *VnetConfig, st *jailState) error {
	// ifconfig prints the name of the "a" leg; the "b" leg differs in the
	// last character.
	out, err := run(ctx, logger, pathIfconfig, "epair", "create")
	if err != nil {
		return fmt.Errorf("creating epair: %w", err)
	}
	hostSide := strings.TrimSpace(out)
	if !strings.HasSuffix(hostSide, "a") {
		return fmt.Errorf("creating epair: expected a name ending in \"a\", got %q", hostSide)
	}
	st.Epair = hostSide
	jailSide := hostSide[:len(hostSide)-1] + "b"

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

	// Hand the jail side over.
	if _, err := run(ctx, logger, pathIfconfig, jailSide, "vnet", strconv.Itoa(jid)); err != nil {
		return fmt.Errorf("moving %s into jail %d: %w", jailSide, jid, err)
	}

	return configureVnetInterface(ctx, logger, jid, jailSide, v, st)
}

// configureVnetInterface addresses the jail's leg and sets its default routes,
// with ifconfig(8) and route(8) run through jexec(8).  With no address the
// interface is brought up and left for the task to configure.
func configureVnetInterface(ctx context.Context, logger hclog.Logger, jid int, iface string, v *VnetConfig, st *jailState) error {
	jexec := func(args ...string) error {
		_, err := run(ctx, logger, pathJexec, append([]string{strconv.Itoa(jid)}, args...)...)
		return err
	}

	// A new vnet starts with lo0 down.
	if err := jexec(pathIfconfig, "lo0", "up"); err != nil {
		return fmt.Errorf("bringing up lo0 in the jail: %w", err)
	}
	if err := jexec(pathIfconfig, iface, "up"); err != nil {
		return fmt.Errorf("bringing up %s in the jail: %w", iface, err)
	}
	if v == nil {
		return nil
	}

	if v.Address != "" {
		if err := jexec(pathIfconfig, iface, "inet", v.Address); err != nil {
			return fmt.Errorf("setting %s on %s: %w", v.Address, iface, err)
		}
		ip, _, err := net.ParseCIDR(v.Address)
		if err != nil {
			return fmt.Errorf("vnet address %q: %w", v.Address, err)
		}
		st.IP = ip.String()
	}
	if v.Gateway != "" {
		if err := jexec(pathRoute, "-4", "add", "default", v.Gateway); err != nil {
			return fmt.Errorf("adding default route via %s: %w", v.Gateway, err)
		}
	}

	if v.Address6 != "" {
		if err := jexec(pathIfconfig, iface, "inet6", v.Address6); err != nil {
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
		if err := jexec(pathRoute, "-6", "add", "default", v.Gateway6); err != nil {
			return fmt.Errorf("adding default IPv6 route via %s: %w", v.Gateway6, err)
		}
	}

	return nil
}

// destroyEpair removes the host leg of a vnet task's epair(4), and the other
// leg with it.
func destroyEpair(ctx context.Context, logger hclog.Logger, st *jailState) error {
	if st.Epair == "" {
		return nil
	}
	if st.Bridge != "" {
		if _, err := run(ctx, logger, pathIfconfig, st.Bridge, "deletem", st.Epair); err != nil {
			logger.Trace("could not remove epair from bridge", "epair", st.Epair,
				"bridge", st.Bridge, "error", err)
		}
	}
	if _, err := run(ctx, logger, pathIfconfig, st.Epair, "destroy"); err != nil {
		// Teardown has to be safe to run twice.
		if interfaceGone(ctx, logger, st.Epair) {
			return nil
		}
		return fmt.Errorf("destroying %s: %w", st.Epair, err)
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
