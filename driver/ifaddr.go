// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"fmt"
	"net"
	"strings"
)

// ifaddrSpec is an address as ip4.addr and ip6.addr take one in jail.conf(5),
// with an optional prefix length and an optional host interface to alias it
// onto:
//
//	10.0.0.5
//	10.0.0.5/24
//	em0|10.0.0.5/24
type ifaddrSpec struct {
	Iface  string
	Addr   string
	Prefix string // the text after "/", either a prefix length or a dotted mask
}

// String renders a spec in the form it was parsed from.
func (s ifaddrSpec) String() string {
	var b strings.Builder
	if s.Iface != "" {
		b.WriteString(s.Iface)
		b.WriteByte('|')
	}
	b.WriteString(s.Addr)
	if s.Prefix != "" {
		b.WriteByte('/')
		b.WriteString(s.Prefix)
	}
	return b.String()
}

func (s ifaddrSpec) isV6() bool { return net.ParseIP(s.Addr).To4() == nil }

func parseIfaddr(spec string) (ifaddrSpec, error) {
	var out ifaddrSpec
	rest := spec
	if iface, after, found := strings.Cut(spec, "|"); found {
		out.Iface, rest = iface, after
	}
	out.Addr, out.Prefix, _ = strings.Cut(rest, "/")
	if net.ParseIP(out.Addr) == nil {
		return ifaddrSpec{}, fmt.Errorf("%q: %q is not an IP address", spec, out.Addr)
	}
	return out, nil
}

// ifconfigAliasArgs builds the ifconfig(8) arguments that add or remove an
// alias, as jail(8) does: a bare IPv4 address gets a host netmask, a dotted
// mask goes as "netmask", and a prefix length goes in CIDR form.
func (s ifaddrSpec) ifconfigAliasArgs(remove bool) []string {
	family := "inet"
	if s.isV6() {
		family = "inet6"
	}
	args := []string{s.Iface, family}

	switch {
	case s.Prefix == "" && !s.isV6():
		args = append(args, s.Addr, "netmask", "255.255.255.255")
	case s.Prefix == "":
		args = append(args, s.Addr, "prefixlen", "128")
	case strings.Contains(s.Prefix, "."):
		args = append(args, s.Addr, "netmask", s.Prefix)
	default:
		args = append(args, s.Addr+"/"+s.Prefix)
	}

	if remove {
		return append(args, "-alias")
	}
	return append(args, "alias")
}
