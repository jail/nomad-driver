// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jail/nomad-driver/jail"
)

// jailParams builds the parameters of a task's jail.  The driver owns those
// that identify the jail, its filesystem and its network; Validate keeps
// jail_params off them.
func jailParams(tc *TaskConfig, st *jailState, mode string, hostname string) ([]jail.Param, error) {
	params := []jail.Param{
		{Name: jail.ParamName, Value: st.Name},
		{Name: jail.ParamPath, Value: st.Root},
		{Name: "host.hostname", Value: hostname},

		// The task's process is started after jail_set(2) returns, and
		// without this the kernel would remove a jail with no process
		// in it.
		{Name: jail.ParamPersist},

		{Name: "enforce_statfs", Value: strconv.Itoa(tc.EnforceStatfs)},

		{Name: "children.max", Value: strconv.Itoa(tc.ChildrenMax)},
	}

	if tc.Securelevel >= 0 {
		params = append(params, jail.IntParam("securelevel", tc.Securelevel))
	}

	// For any devfs the task mounts itself.
	if tc.MountDevfs {
		params = append(params, jail.IntParam("devfs_ruleset", devfsRuleset(tc, mode)))
	}

	netParams, err := jailNetworkParams(tc, st, mode)
	if err != nil {
		return nil, err
	}
	params = append(params, netParams...)

	for _, a := range tc.Allow {
		params = append(params, jail.Param{Name: "allow." + a, Value: "true"})
	}

	// Sorted, so that the call and any error from it are reproducible.
	passthrough := tc.JailParams.merged()
	extra := make([]string, 0, len(passthrough))
	for name := range passthrough {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	for _, name := range extra {
		params = append(params, jail.Param{Name: name, Value: passthrough[name]})
	}

	return params, nil
}

// jailNetworkParams turns a network mode into jail parameters.
func jailNetworkParams(tc *TaskConfig, st *jailState, mode string) ([]jail.Param, error) {
	switch mode {
	case NetworkInherit:
		return []jail.Param{
			{Name: "ip4", Value: "inherit"},
			{Name: "ip6", Value: "inherit"},
		}, nil

	case NetworkNone:
		return []jail.Param{
			{Name: "ip4", Value: "disable"},
			{Name: "ip6", Value: "disable"},
		}, nil

	case NetworkVnet:
		if !jail.HasParam("vnet") {
			return nil, fmt.Errorf("network_mode = %q needs a kernel built with VIMAGE", NetworkVnet)
		}
		// The epair leg is moved in once the jail exists; see
		// createVnet.
		return []jail.Param{{Name: "vnet", Value: "new"}}, nil

	case NetworkAlias:
		// The kernel takes bare addresses.  The interface and prefix
		// length of "em0|10.0.0.5/24" describe an alias on the host,
		// which configureAliases adds, as jail(8) would.
		var params []jail.Param
		v4, err := bareAddrs(tc.IP4Addr)
		if err != nil {
			return nil, err
		}
		v6, err := bareAddrs(tc.IP6Addr)
		if err != nil {
			return nil, err
		}
		if len(v4) > 0 {
			params = append(params, jail.Param{Name: "ip4.addr", Value: strings.Join(v4, ",")})
		} else {
			params = append(params, jail.Param{Name: "ip4", Value: "disable"})
		}
		if len(v6) > 0 {
			params = append(params, jail.Param{Name: "ip6.addr", Value: strings.Join(v6, ",")})
		} else {
			params = append(params, jail.Param{Name: "ip6", Value: "disable"})
		}
		return params, nil
	}

	return nil, badNetworkMode(mode)
}

func bareAddrs(specs []string) ([]string, error) {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		spec, err := parseIfaddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, spec.Addr)
	}
	return out, nil
}

// devfsRuleset picks the ruleset for a task's /dev.  It never returns 0, which
// hides nothing.
func devfsRuleset(tc *TaskConfig, mode string) int {
	switch {
	case tc.DevfsRuleset != 0:
		return tc.DevfsRuleset
	case mode == NetworkVnet:
		// devfsrules_jail_vnet also exposes bpf, for dhclient(8).
		return devfsRulesetJailVnet
	default:
		return devfsRulesetJail
	}
}
