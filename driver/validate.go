// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"fmt"
	"net"
	"strings"
)

// validateCIDR accepts an address with a prefix length: 10.88.0.5/24,
// 2001:db8::5/64.
func validateCIDR(s string, v6 bool) error {
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("%q is not an address with a prefix length: %w", s, err)
	}
	return checkFamily(ip, v6, s)
}

func validateIP(s string, v6 bool) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("%q is not an IP address", s)
	}
	return checkFamily(ip, v6, s)
}

func checkFamily(ip net.IP, v6 bool, s string) error {
	if isV6 := ip.To4() == nil; isV6 != v6 {
		want := "IPv4"
		if v6 {
			want = "IPv6"
		}
		return fmt.Errorf("%q is not an %s address", s, want)
	}
	return nil
}

// validateMAC accepts an Ethernet address as ifconfig(8) takes one.
func validateMAC(s string) error {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return fmt.Errorf("%q is not a MAC address: %w", s, err)
	}
	if len(hw) != 6 {
		return fmt.Errorf("%q is not a 48-bit Ethernet address", s)
	}
	if hw[0]&1 != 0 {
		return fmt.Errorf("%q has the group bit set, which is not valid for an interface", s)
	}
	return nil
}

// validateAliasAddr accepts an entry of ip4.addr or ip6.addr as jail.conf(5)
// has it:
//
//	10.0.0.5
//	10.0.0.5/24
//	em0|10.0.0.5/24
func validateAliasAddr(s string) error {
	spec := s
	if iface, rest, found := strings.Cut(s, "|"); found {
		if !validInterfaceName(iface) {
			return fmt.Errorf("%q: %q is not a valid interface name", s, iface)
		}
		spec = rest
	}
	if spec == "" {
		return fmt.Errorf("%q has no address", s)
	}
	addr, _, found := strings.Cut(spec, "/")
	if net.ParseIP(addr) == nil {
		return fmt.Errorf("%q: %q is not an IP address", s, addr)
	}
	if found {
		if _, _, err := net.ParseCIDR(spec); err != nil {
			return fmt.Errorf("%q: %w", s, err)
		}
	}
	return nil
}

// validInterfaceName reports whether s could name a network interface.  The
// names go to ifconfig(8), so nothing it could read as anything else is
// allowed, a leading "-" included.
func validInterfaceName(s string) bool {
	if s == "" || len(s) > 15 || !isAlnum(rune(s[0])) {
		return false
	}
	for _, r := range s {
		if !isAlnum(r) && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// validDatasetName reports whether s is a ZFS dataset name: components of
// letters, digits and "_-.:" joined by "/", the pool starting with a letter.
// The names go to zfs(8).
func validDatasetName(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for _, component := range strings.Split(s, "/") {
		if !validDatasetComponent(component) {
			return false
		}
	}
	return true
}

func validDatasetComponent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isAlnum(r) && r != '_' && r != '-' && r != '.' && r != ':' {
			return false
		}
	}
	return true
}

// snapshotDataset returns the dataset that dataset@snapshot is a snapshot of,
// and false if s is not a well-formed snapshot name.
func snapshotDataset(s string) (string, bool) {
	dataset, snapshot, found := strings.Cut(s, "@")
	if !found || !validDatasetName(dataset) || !validDatasetComponent(snapshot) {
		return "", false
	}
	return dataset, true
}
