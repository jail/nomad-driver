// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: MPL-2.0 AND BSD-2-Clause

//go:build freebsd

package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"

	"github.com/jail/nomad-driver/driver"

	_ "github.com/hashicorp/nomad/drivers/shared/executor"
)

func main() {
	plugins.Serve(factory)
}

func factory(log hclog.Logger) interface{} {
	return driver.NewPlugin(log)
}
