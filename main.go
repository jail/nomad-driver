// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: MPL-2.0

// This file is derived from hashicorp/nomad-skeleton-driver-plugin, and so
// remains under the MPL-2.0 that the skeleton carries.

//go:build freebsd

// Command jail-nomad-driver is a Nomad task driver plugin that runs tasks in
// FreeBSD jails. Nomad starts it as a go-plugin child of the client agent; see
// the README for how to install and configure it.
package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"

	"github.com/jail/nomad-driver/driver"

	// Importing the executor package installs the "executor" subcommand this
	// binary is re-executed with. Nomad's shared executor runs as a child
	// process of the plugin, started as `<this binary> executor <config>`, so
	// a driver that uses the executor has to be able to serve it.
	_ "github.com/hashicorp/nomad/drivers/shared/executor"
)

func main() {
	plugins.Serve(factory)
}

func factory(log hclog.Logger) interface{} {
	return driver.NewPlugin(log)
}
