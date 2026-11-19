// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"strings"
	"testing"

	"github.com/jail/nomad-driver/jail"
)

// TestCreateVnetNeedsNothingFromTheImage is the regression test for configuring
// a vnet jail with the image's own ifconfig and route.  The jail is rooted at
// an empty directory.
func TestCreateVnetNeedsNothingFromTheImage(t *testing.T) {
	requireRoot(t)
	if !jail.HasParam("vnet") {
		t.Skip("kernel has no VIMAGE support")
	}
	d := newTestDriver(t)

	out, err := run(d.ctx, d.logger, pathIfconfig, "bridge", "create")
	if err != nil {
		t.Skipf("cannot create a bridge: %v", err)
	}
	bridge := strings.TrimSpace(out)
	t.Cleanup(func() { _, _ = run(context.Background(), d.logger, pathIfconfig, bridge, "destroy") })

	name, _ := testJail(t, "nomad-vnet-", jail.Param{Name: "vnet", Value: "new"})
	st := &jailState{Name: name}
	t.Cleanup(func() { _ = d.teardown(d.logger, st) })

	vnet := &VnetConfig{
		Address:  "192.0.2.10/24",
		Gateway:  "192.0.2.1",
		Address6: "2001:db8::10/64",
		Gateway6: "2001:db8::1",
	}
	if err := createVnet(d.ctx, d.logger, bridge, vnet, st); err != nil {
		t.Fatalf("createVnet: %v", err)
	}
	if st.IP != "192.0.2.10" {
		t.Errorf("reported address = %q, want 192.0.2.10", st.IP)
	}
	if st.Epair != epairHostName(name) {
		t.Errorf("host leg = %q, want the derived name %q", st.Epair, epairHostName(name))
	}

	inJail := func(tool string, args ...string) string {
		t.Helper()
		out, err := run(d.ctx, d.logger, tool, append([]string{"-j", name}, args...)...)
		if err != nil {
			t.Fatalf("%s -j %s %v: %v", tool, name, args, err)
		}
		return out
	}
	addrs := inJail(pathIfconfig, "-a")
	for _, want := range []string{"inet 192.0.2.10", "inet6 2001:db8::10", "inet 127.0.0.1", "inet6 ::1"} {
		if !strings.Contains(addrs, want) {
			t.Errorf("the jail's interfaces lack %q:\n%s", want, addrs)
		}
	}
	if route := inJail(pathRoute, "-n", "-4", "get", "default"); !strings.Contains(route, "gateway: 192.0.2.1") {
		t.Errorf("the jail's IPv4 default route is not via 192.0.2.1:\n%s", route)
	}
	if route := inJail(pathRoute, "-n", "-6", "get", "default"); !strings.Contains(route, "gateway: 2001:db8::1") {
		t.Errorf("the jail's IPv6 default route is not via 2001:db8::1:\n%s", route)
	}

	if err := d.teardown(d.logger, st); err != nil {
		t.Errorf("teardown: %v", err)
	}
	if !interfaceGone(d.ctx, d.logger, epairHostName(name)) {
		t.Errorf("%s outlived the task", epairHostName(name))
	}
}
