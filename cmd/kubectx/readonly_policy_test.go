package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ahmetb/kubectx/internal/proxy"
)

func TestIsPolicyTrigger(t *testing.T) {
	yes := []string{
		"-r", "--readonly",
		"--mode", "--mode=relaxed",
		"--policy", "--policy=ro.yaml",
		"--allow-write", "--allow-write=configmaps",
		"--namespace", "-n", "--namespace=dev",
		"--allow-exec",
	}
	no := []string{"-s", "-d", "prod", "--help", "-h", "--shell", "ctx-name", "-c",
		"--mode-something", "--policyfile", "--allow-writes", "--n", ""}
	for _, a := range yes {
		if !isPolicyTrigger(a) {
			t.Errorf("isPolicyTrigger(%q) = false, want true", a)
		}
	}
	for _, a := range no {
		if isPolicyTrigger(a) {
			t.Errorf("isPolicyTrigger(%q) = true, want false", a)
		}
	}
}

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
		{"allow-exec rejects value", []string{"--allow-exec=true", "prod"},
			"", ReadonlyPolicyFlags{}, true},
		{"allow-exec rejects value false", []string{"--allow-exec=false", "prod"},
			"", ReadonlyPolicyFlags{}, true},
		{"csv trims whitespace and empties", []string{"--allow-write= configmaps , , secrets ", "prod"},
			"prod", ReadonlyPolicyFlags{AllowWrite: []string{"configmaps", "secrets"}}, false},
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
	zero, err := ReadonlyPolicyFlags{}.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(zero, proxy.PresetStrict()) {
		t.Errorf("zero flags -> PresetStrict, got %+v", zero)
	}

	t.Run("preset + extras layered", func(t *testing.T) {
		got, err := ReadonlyPolicyFlags{
			Mode:       "relaxed",
			AllowWrite: []string{"namespaces"},
			AllowExec:  true,
			Namespaces: []string{"dev"},
		}.buildPolicy()
		if err != nil {
			t.Fatal(err)
		}
		want := proxy.Policy{
			Name:         "relaxed+exec,writes,ns",
			AllowUpgrade: true,
			AllowWriteResources: []proxy.ResourceRule{
				{Resource: "configmaps"},
				{Resource: "secrets"},
				{Group: "apps", Resource: "deployments"},
				{Group: "apps", Resource: "statefulsets"},
				{Resource: "namespaces"},
			},
			Namespaces: []string{"dev"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("buildPolicy() = %+v\nwant %+v", got, want)
		}
	})

	t.Run("allow-exec alone renames strict to strict+exec", func(t *testing.T) {
		got, err := ReadonlyPolicyFlags{AllowExec: true}.buildPolicy()
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "strict+exec" {
			t.Errorf("expected name strict+exec, got %q", got.Name)
		}
		if !got.AllowUpgrade {
			t.Error("expected AllowUpgrade=true")
		}
	})

	t.Run("unknown mode bubbles up", func(t *testing.T) {
		if _, err := (ReadonlyPolicyFlags{Mode: "bogus"}).buildPolicy(); err == nil {
			t.Error("expected error for unknown mode")
		}
	})

	t.Run("mode + policy file rejected", func(t *testing.T) {
		_, err := (ReadonlyPolicyFlags{Mode: "relaxed", PolicyFile: "ro.yaml"}).buildPolicy()
		if err == nil {
			t.Fatal("expected error when both --mode and --policy are given")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid resource token surfaces parse error", func(t *testing.T) {
		_, err := (ReadonlyPolicyFlags{AllowWrite: []string{"apps/"}}).buildPolicy()
		if err == nil {
			t.Error("expected error for invalid resource token")
		}
	})
}
