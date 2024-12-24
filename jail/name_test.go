// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import "testing"

func TestNegateName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"persist", "nopersist"},
		{"allow.mount", "allow.nomount"},
		{"allow.mount.zfs", "allow.mount.nozfs"},
		{"ip4.saddrsel", "ip4.nosaddrsel"},
	}
	for _, tc := range tests {
		if got := negateName(tc.in); got != tc.want {
			t.Errorf("negateName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAffirmName(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "nopersist", want: "persist"},
		{in: "allow.nomount", want: "allow.mount"},
		{in: "allow.mount.nozfs", want: "allow.mount.zfs"},
		{in: "persist", wantErr: true},
		{in: "allow.mount", wantErr: true},
	}
	for _, tc := range tests {
		got, err := affirmName(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("affirmName(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("affirmName(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
		}
	}
}

func TestNegateAffirmAreInverses(t *testing.T) {
	for _, name := range []string{"persist", "allow.mount", "allow.mount.zfs", "ip4.saddrsel"} {
		got, err := affirmName(negateName(name))
		if err != nil || got != name {
			t.Errorf("affirmName(negateName(%q)) = %q, %v", name, got, err)
		}
	}
}

func TestKeyValueName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"env.PATH", "env"},
		{"meta.owner", "meta"},
		{"persist", ""},
		{"allow.mount.zfs", "allow"},
	}
	for _, tc := range tests {
		if got := keyValueName(tc.in); got != tc.want {
			t.Errorf("keyValueName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
