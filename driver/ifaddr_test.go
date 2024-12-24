// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"strings"
	"testing"
)

func TestParseIfaddr(t *testing.T) {
	tests := []struct {
		in      string
		want    ifaddrSpec
		wantErr bool
	}{
		{in: "10.0.0.5", want: ifaddrSpec{Addr: "10.0.0.5"}},
		{in: "10.0.0.5/24", want: ifaddrSpec{Addr: "10.0.0.5", Prefix: "24"}},
		{in: "em0|10.0.0.5/24", want: ifaddrSpec{Iface: "em0", Addr: "10.0.0.5", Prefix: "24"}},
		{in: "em0|10.0.0.5/255.255.255.0", want: ifaddrSpec{Iface: "em0", Addr: "10.0.0.5", Prefix: "255.255.255.0"}},
		{in: "lo0|2001:db8::5/64", want: ifaddrSpec{Iface: "lo0", Addr: "2001:db8::5", Prefix: "64"}},
		{in: "2001:db8::5", want: ifaddrSpec{Addr: "2001:db8::5"}},
		{in: "em0|", wantErr: true},
		{in: "not-an-address", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseIfaddr(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseIfaddr(%q) = %+v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIfaddr(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseIfaddr(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			if round := got.String(); round != tc.in {
				t.Errorf("String() = %q, want %q", round, tc.in)
			}
		})
	}
}

// TestIfconfigAliasArgs checks the command against what jail(8) builds for the
// same ip4.addr or ip6.addr entry; see IP__IP4_IFADDR in
// usr.sbin/jail/command.c.
func TestIfconfigAliasArgs(t *testing.T) {
	tests := []struct {
		in     string
		remove bool
		want   string
	}{
		{
			in:   "em0|10.0.0.5",
			want: "em0 inet 10.0.0.5 netmask 255.255.255.255 alias",
		},
		{
			in:   "em0|10.0.0.5/24",
			want: "em0 inet 10.0.0.5/24 alias",
		},
		{
			in:   "em0|10.0.0.5/255.255.255.0",
			want: "em0 inet 10.0.0.5 netmask 255.255.255.0 alias",
		},
		{
			in:   "em0|10.0.0.5/24",
			want: "em0 inet 10.0.0.5/24 -alias", remove: true,
		},
		{
			in:   "em0|2001:db8::5/64",
			want: "em0 inet6 2001:db8::5/64 alias",
		},
		{
			in:   "em0|2001:db8::5",
			want: "em0 inet6 2001:db8::5 prefixlen 128 alias",
		},
	}

	for _, tc := range tests {
		t.Run(tc.in+"/"+tc.want, func(t *testing.T) {
			spec, err := parseIfaddr(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(spec.ifconfigAliasArgs(tc.remove), " ")
			if got != tc.want {
				t.Errorf("ifconfigAliasArgs = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidInterfaceName(t *testing.T) {
	ok := []string{"em0", "bridge0", "epair0a", "vlan.100", "lagg0", "my_if-1"}
	bad := []string{"", "thisnameiswaytoolong", "em0;reboot", "em 0", "em0|x", "../../etc"}
	for _, n := range ok {
		if !validInterfaceName(n) {
			t.Errorf("validInterfaceName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validInterfaceName(n) {
			t.Errorf("validInterfaceName(%q) = true, want false", n)
		}
	}
}
