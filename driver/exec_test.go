// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"strings"
	"testing"

	"github.com/hashicorp/nomad/plugins/drivers"
)

func TestJexecCommand(t *testing.T) {
	tests := []struct {
		name string
		user string
		// nativeWorkDir is whether jexec takes -d.
		nativeWorkDir bool
		tc            TaskConfig
		want          string
	}{
		{
			name: "plain command",
			tc:   TaskConfig{Command: "/usr/local/bin/app"},
			want: "/usr/sbin/jexec 7 /usr/local/bin/app",
		},
		{
			name: "command with args",
			tc:   TaskConfig{Command: "/usr/local/bin/app", Args: []string{"-f", "/local/app.conf"}},
			want: "/usr/sbin/jexec 7 /usr/local/bin/app -f /local/app.conf",
		},
		{
			name: "user is resolved inside the jail",
			user: "www",
			tc:   TaskConfig{Command: "/usr/local/bin/app"},
			want: "/usr/sbin/jexec -U www 7 /usr/local/bin/app",
		},
		{
			name:          "work_dir goes to jexec -d where it is supported",
			nativeWorkDir: true,
			tc:            TaskConfig{Command: "/usr/local/bin/app", Args: []string{"-v"}, WorkDir: "/srv"},
			want:          "/usr/sbin/jexec -d /srv 7 /usr/local/bin/app -v",
		},
		{
			name:          "work_dir with a user",
			nativeWorkDir: true,
			user:          "www",
			tc:            TaskConfig{Command: "/usr/local/bin/app", WorkDir: "/srv"},
			want:          "/usr/sbin/jexec -d /srv -U www 7 /usr/local/bin/app",
		},
		{
			name: "work_dir falls back to a shell on an older jexec",
			tc:   TaskConfig{Command: "/usr/local/bin/app", Args: []string{"-v"}, WorkDir: "/srv"},
			want: "/usr/sbin/jexec 7 /bin/sh -c cd '/srv' && exec '/usr/local/bin/app' '-v'",
		},
		{
			name:          "no work_dir means no shell even where -d exists",
			nativeWorkDir: true,
			tc:            TaskConfig{Command: "/usr/local/bin/app"},
			want:          "/usr/sbin/jexec 7 /usr/local/bin/app",
		},
		{
			name: "a quote in an argument cannot break out of the fallback shell word",
			tc: TaskConfig{
				Command: "/bin/echo",
				Args:    []string{"it's; rm -rf /"},
				WorkDir: "/srv",
			},
			want: `/usr/sbin/jexec 7 /bin/sh -c cd '/srv' && exec '/bin/echo' 'it'\''s; rm -rf /'`,
		},
		{
			name:          "an argument needs no quoting when jexec takes the directory",
			nativeWorkDir: true,
			tc: TaskConfig{
				Command: "/bin/echo",
				Args:    []string{"it's; rm -rf /"},
				WorkDir: "/srv",
			},
			want: "/usr/sbin/jexec -d /srv 7 /bin/echo it's; rm -rf /",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, args := jexecCommand(7, &drivers.TaskConfig{User: tc.user}, &tc.tc, tc.nativeWorkDir)
			got := strings.Join(append([]string{cmd}, args...), " ")
			if got != tc.want {
				t.Errorf("jexecCommand =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

// TestJexecCommandNeedsNoShellWithNativeWorkDir is the point of probing for -d:
// an image with no /bin/sh can still be given a working directory.
func TestJexecCommandNeedsNoShellWithNativeWorkDir(t *testing.T) {
	_, args := jexecCommand(7, &drivers.TaskConfig{},
		&TaskConfig{Command: "/app", WorkDir: "/srv"}, true)
	for _, a := range args {
		if a == pathShell {
			t.Fatalf("jexec -d is available but the command still goes through %s: %v", pathShell, args)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/srv", "'/srv'"},
		{"a b", "'a b'"},
		{"it's", `'it'\''s'`},
		{"$(reboot)", "'$(reboot)'"},
		{"", "''"},
	}
	for _, tc := range tests {
		if got := shellQuote(tc.in); got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
