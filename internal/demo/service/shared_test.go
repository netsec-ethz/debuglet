// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func freshSharedFixture(t *testing.T) (*fixture, Profile, Request) {
	t.Helper()
	f, p, r := enrolledReplacementFixture(t)
	if err := os.Remove(RecordPath(f.root, p.Role, p.Name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.UnitPath); err != nil {
		t.Fatal(err)
	}
	p.ExecutorID = ""
	p.SharedIsolation = true
	r.User, r.Group, r.Isolation = p.User, p.Group, "shared"
	return f, p, r
}

func TestManagedSharedAdoptionAndReplacementPreserveState(t *testing.T) {
	f, p, r := freshSharedFixture(t)
	before := replacementSnapshot(t, p, false)
	for n := 0; n < 2; n++ {
		report, err := f.installer.Install(t.Context(), r, f.assets, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 && len(report.Changed) != 0 {
			t.Fatalf("reinstall changed: %+v", report)
		}
		p, err = ReadRecord(f.root, p.Role, p.Name)
		if err != nil || !p.SharedIsolation {
			t.Fatalf("profile lost: %+v %v", p, err)
		}
		if n == 0 {
			cfg, err := readEnrolledConfig(p)
			if err != nil || cfg.Isolation != sharedPreset(p) {
				t.Fatalf("preset: %+v %v", cfg, err)
			}
			after := replacementSnapshot(t, p, false)
			delete(before, p.ConfigPath)
			delete(after, p.ConfigPath)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("enrollment or retained data changed")
			}
		}
		r.Isolation = "" // The installed profile, not the new CLI default, wins.
	}
	unit, err := Unit(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"Delegate=cpu memory pids", "DelegateSubgroup=control", "MemoryMax=1342177280", "CPUQuota=225%", "TasksMax=384", "ProtectControlGroups=no"} {
		if !strings.Contains(unit, setting+"\n") {
			t.Fatalf("missing %s", setting)
		}
	}
	retained := replacementSnapshot(t, p, false)
	target := replacementTarget(t, f, p, "1.4.3", "exit 0")
	if _, err := f.installer.ReplacePackage(t.Context(), r, target); err != nil {
		t.Fatal(err)
	}
	p, err = ReadRecord(f.root, p.Role, p.Name)
	if err != nil || !p.SharedIsolation {
		t.Fatalf("replacement lost shared: %v", err)
	}
	if !reflect.DeepEqual(retained, replacementSnapshot(t, p, false)) {
		t.Fatal("replacement rewrote shared configuration")
	}
	data, err := os.ReadFile(p.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(data), "profile = 'shared'", "profile = 'trusted'", 1)
	if changed == string(data) {
		t.Fatal("missing shared profile in fixture")
	}
	if err := os.WriteFile(p.ConfigPath, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.installer.prepareStart(t.Context(), p); err == nil {
		t.Fatal("start accepted downgraded isolation")
	}
	if _, err := f.installer.ReplacePackage(t.Context(), r, target); err == nil {
		t.Fatal("replacement accepted downgraded isolation")
	}
	if _, err := readEnrolledConfig(p); err == nil {
		t.Fatal("retained config accepted downgraded isolation")
	}
	loaded, _, err := f.installer.load(t.Context(), "status", p.Role, p.Name)
	if err != nil || !loaded.SharedIsolation {
		t.Fatalf("load lost shared: %v", err)
	}
}

func TestManagedSharedRefusesConfigurationChanges(t *testing.T) {
	for _, section := range []string{"[isolation]\nprofile = 'trusted'\n", "[isolation]\n", "[Isolation]\nprofile = 'trusted'\n"} {
		t.Run(section, func(t *testing.T) {
			f, p, r := freshSharedFixture(t)
			data, _ := os.ReadFile(p.ConfigPath)
			if err := os.WriteFile(p.ConfigPath, append(data, []byte("\n"+section)...), 0600); err != nil {
				t.Fatal(err)
			}
			before := replacementSnapshot(t, p, false)
			if _, err := f.installer.Install(t.Context(), r, f.assets, false, false); err == nil {
				t.Fatal("custom isolation accepted")
			}
			if !reflect.DeepEqual(before, replacementSnapshot(t, p, false)) {
				t.Fatal("refusal changed state")
			}
		})
	}
	f, p, r := enrolledReplacementFixture(t)
	r.User, r.Group, r.Isolation = p.User, p.Group, "shared"
	before := replacementSnapshot(t, p, true)
	if _, err := f.installer.Install(t.Context(), r, f.assets, false, false); err == nil {
		t.Fatal("existing profile changed")
	}
	if _, err := f.installer.ReplacePackage(t.Context(), r, f.assets); err == nil {
		t.Fatal("replacement accepted profile change")
	}
	if !reflect.DeepEqual(before, replacementSnapshot(t, p, true)) {
		t.Fatal("refusal changed existing installation")
	}
}

func TestManagedSharedRecoversConfigurationBeforeRecord(t *testing.T) {
	f, p, r := freshSharedFixture(t)
	changed, err := prepareSharedConfig(p)
	if err != nil || !changed {
		t.Fatalf("prepare: %v %v", changed, err)
	}
	before := replacementSnapshot(t, p, false)
	if _, err := f.installer.Install(t.Context(), r, f.assets, false, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, replacementSnapshot(t, p, false)) {
		t.Fatal("retry changed configuration")
	}
}

func TestManagedSharedRequiresEnrolledExecutor(t *testing.T) {
	f := newFixture(t)
	for _, r := range []Request{
		{Role: storagecheck.Executor, Name: "worker", Isolation: "shared"},
		{Role: storagecheck.Dispatcher, Name: "local", Isolation: "shared"},
		{Role: storagecheck.Executor, Name: "worker", Isolation: "trusted", EnrolledState: StateDirectory(f.root, storagecheck.Executor, "worker")},
	} {
		r.Root = f.root
		if _, err := Resolve(r, f.assets); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
