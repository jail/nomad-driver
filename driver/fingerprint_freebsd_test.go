// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/nomad/plugins/drivers"
)

func TestExecutable(t *testing.T) {
	dir := t.TempDir()
	tool, data := filepath.Join(dir, "tool"), filepath.Join(dir, "data")
	if err := os.WriteFile(tool, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if !executable(tool) {
		t.Error("an executable file was not recognised as one")
	}
	for name, path := range map[string]string{
		"a file without the execute bit": data,
		"a directory":                    dir,
		"nothing at all":                 filepath.Join(dir, "missing"),
	} {
		if executable(path) {
			t.Errorf("%s was taken for something the driver could run", name)
		}
	}
}

// TestFingerprintAgreesWithTheHost checks that a healthy fingerprint is only
// given on a host the driver could start a task on.
func TestFingerprintAgreesWithTheHost(t *testing.T) {
	requireRoot(t)
	d := newTestDriver(t)

	fp := d.buildFingerprint()
	if !executable(pathJexec) {
		if fp.Health != drivers.HealthStateUndetected {
			t.Errorf("health = %s on a host without %s, want undetected", fp.Health, pathJexec)
		}
		return
	}
	if err := checkDevfsRuleset(d.ctx, d.logger, devfsRulesetJail); err != nil {
		if fp.Health != drivers.HealthStateUndetected {
			t.Errorf("health = %s on a host whose jail ruleset is not loaded, want undetected", fp.Health)
		}
		return
	}
	if fp.Health != drivers.HealthStateHealthy {
		t.Fatalf("health = %s (%s), want healthy", fp.Health, fp.HealthDescription)
	}
	for _, attr := range []string{attrVersion, attrVnet, attrZFS, attrRCTL, attrJexecWorkDir} {
		if _, ok := fp.Attributes[attr]; !ok {
			t.Errorf("a healthy fingerprint lacks %s", attr)
		}
	}
}
