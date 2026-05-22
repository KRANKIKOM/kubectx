package main

import (
	"reflect"
	"testing"
)

func TestParseReadonlyFlags(t *testing.T) {
	tests := []struct {
		name       string
		argv       []string
		wantTarget string
		wantFlags  ReadonlyPolicyFlags
		wantErr    bool
	}{
		{"just context", []string{"prod"}, "prod", ReadonlyPolicyFlags{}, false},
		{"flags before context", []string{"--mode=relaxed", "prod"},
			"prod", ReadonlyPolicyFlags{Mode: "relaxed"}, false},
		{"flags after context", []string{"prod", "--allow-exec"},
			"prod", ReadonlyPolicyFlags{AllowExec: true}, false},
		{"separate value", []string{"--mode", "debug", "prod"},
			"prod", ReadonlyPolicyFlags{Mode: "debug"}, false},
		{"allow-write csv", []string{"--allow-write=configmaps,apps/deployments", "prod"},
			"prod", ReadonlyPolicyFlags{AllowWrite: []string{"configmaps", "apps/deployments"}}, false},
		{"namespace csv", []string{"-n", "dev,staging", "prod"},
			"prod", ReadonlyPolicyFlags{Namespaces: []string{"dev", "staging"}}, false},
		{"policy file", []string{"--policy=ro.yaml", "prod"},
			"prod", ReadonlyPolicyFlags{PolicyFile: "ro.yaml"}, false},
		{"interactive (no target)", []string{"--mode=relaxed"},
			"", ReadonlyPolicyFlags{Mode: "relaxed"}, false},
		{"unknown flag", []string{"--bogus", "prod"},
			"", ReadonlyPolicyFlags{}, true},
		{"two contexts is error", []string{"a", "b"},
			"", ReadonlyPolicyFlags{}, true},
		{"missing value", []string{"--mode"},
			"", ReadonlyPolicyFlags{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, flags, err := parseReadonlyFlags(tt.argv)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if target != tt.wantTarget {
				t.Errorf("target=%q, want %q", target, tt.wantTarget)
			}
			if !reflect.DeepEqual(flags, tt.wantFlags) {
				t.Errorf("flags=%+v, want %+v", flags, tt.wantFlags)
			}
		})
	}
}

func TestBuildPolicy(t *testing.T) {
	// zero flags -> nil policy (use strict default)
	p, err := ReadonlyPolicyFlags{}.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("expected nil policy for zero flags, got %+v", p)
	}

	// mode + extras layered on top
	p, err = ReadonlyPolicyFlags{
		Mode:       "relaxed",
		AllowWrite: []string{"namespaces"},
		AllowExec:  true,
		Namespaces: []string{"dev"},
	}.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.AllowUpgrade {
		t.Error("expected AllowUpgrade=true")
	}
	if !contains(p.AllowWriteResources, "namespaces") {
		t.Errorf("expected namespaces in AllowWriteResources, got %v", p.AllowWriteResources)
	}
	if !contains(p.Namespaces, "dev") {
		t.Errorf("expected dev in Namespaces, got %v", p.Namespaces)
	}

	// unknown mode bubbles up
	if _, err := (ReadonlyPolicyFlags{Mode: "bogus"}).buildPolicy(); err == nil {
		t.Error("expected error for unknown mode")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
