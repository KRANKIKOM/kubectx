package proxy

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writePolicyFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPolicyFile_RoundTrip(t *testing.T) {
	path := writePolicyFile(t, "ro.yaml", `
name: my-policy
allowUpgrade: true
namespaces: [dev, staging]
allowWriteResources:
  - configmaps
  - apps/deployments
  - "*"
`)
	p, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Policy{
		Name:         "my-policy",
		AllowUpgrade: true,
		Namespaces:   []string{"dev", "staging"},
		AllowWriteResources: []ResourceRule{
			{Resource: "configmaps"},
			{Group: "apps", Resource: "deployments"},
			{All: true},
		},
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("LoadPolicyFile() = %+v, want %+v", p, want)
	}
}

func TestLoadPolicyFile_DefaultNameIsBasename(t *testing.T) {
	path := writePolicyFile(t, "ro.yaml", "allowUpgrade: true\n")
	p, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "ro.yaml" {
		t.Errorf("default Name = %q, want basename %q", p.Name, "ro.yaml")
	}
}

func TestLoadPolicyFile_MissingFile(t *testing.T) {
	_, err := LoadPolicyFile("/nonexistent/path/to/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPolicyFile_MalformedYAML(t *testing.T) {
	path := writePolicyFile(t, "bad.yaml", "name: ok\nallowUpgrade: not-a-bool\n")
	_, err := LoadPolicyFile(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadPolicyFile_UnknownFieldRejected(t *testing.T) {
	// Typo footgun: `allowWriteResource` (no final s) used to silently
	// produce a deny-all policy. UnmarshalStrict must reject it.
	path := writePolicyFile(t, "typo.yaml", `
name: typo
allowWriteResource:
  - configmaps
`)
	_, err := LoadPolicyFile(path)
	if err == nil {
		t.Fatal("expected strict-unmarshal error for unknown field")
	}
	if !strings.Contains(err.Error(), "allowWriteResource") {
		t.Errorf("error should mention the unknown field; got %v", err)
	}
}

func TestLoadPolicyFile_EmptyResourceTokenRejected(t *testing.T) {
	path := writePolicyFile(t, "empty-token.yaml", `
allowWriteResources:
  - ""
`)
	_, err := LoadPolicyFile(path)
	if err == nil {
		t.Fatal("expected error for empty resource token")
	}
}

func TestLoadPolicyFile_MalformedResourceTokenRejected(t *testing.T) {
	path := writePolicyFile(t, "bad-token.yaml", `
allowWriteResources:
  - apps/
`)
	_, err := LoadPolicyFile(path)
	if err == nil {
		t.Fatal("expected error for malformed resource token")
	}
}

func TestLoadPolicyFile_EmptyFileIsStrict(t *testing.T) {
	path := writePolicyFile(t, "empty.yaml", "")
	p, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// An empty file produces a near-zero Policy (Name defaults to filename),
	// which behaves identically to PresetStrict.
	r := httptest.NewRequest("DELETE", "/api/v1/namespaces/foo/pods/p1", nil)
	if _, ok := p.Decide(r); ok {
		t.Error("empty policy file should still block writes")
	}
}
