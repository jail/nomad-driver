# Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
#
# SPDX-License-Identifier: BSD-2-Clause

PLUGIN_BINARY = jail-nomad-driver

# The driver needs jail(2), so a release build is a FreeBSD one.  The rest of
# the module builds, vets and tests anywhere.
GOOS ?= freebsd

.PHONY: default build clean test vet lint fmt check

default: build

build:
	GOOS=$(GOOS) go build -trimpath -o $(PLUGIN_BINARY) .

clean:
	rm -f $(PLUGIN_BINARY)
	go clean -testcache

# Tests that create jails, mount filesystems or clone datasets skip themselves
# unless run as root, so run this both ways.
test:
	go test -count=1 ./...

vet:
	GOOS=$(GOOS) go vet ./...
	go vet ./...

# staticcheck has to be built with this module's toolchain, for the host, and
# run with GOOS=freebsd: elsewhere the build tags hide most of the driver, and
# what it uses looks dead.  Setting GOOS for go run would build it for FreeBSD
# as well, so it is set for the program alone.
lint: vet
	GOOS= GOARCH= go run -exec "env GOOS=$(GOOS)" \
	    honnef.co/go/tools/cmd/staticcheck@latest ./...

fmt:
	gofmt -l -w .

check: lint test
