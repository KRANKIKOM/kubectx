package proxy

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseAPIPath(t *testing.T) {
	tests := []struct {
		path string
		want APIPath
	}{
		{"/api/v1/pods", APIPath{Version: "v1", Resource: "pods"}},
		{"/api/v1/pods/", APIPath{Version: "v1", Resource: "pods"}},
		{"/api/v1/namespaces/foo", APIPath{Version: "v1", Resource: "namespaces", Name: "foo"}},
		{"/api/v1/namespaces/foo/status", APIPath{Version: "v1", Resource: "namespaces", Name: "foo", Subresource: "status"}},
		{"/api/v1/namespaces/foo/finalize", APIPath{Version: "v1", Resource: "namespaces", Name: "foo", Subresource: "finalize"}},
		{"/api/v1/namespaces/foo/pods", APIPath{Version: "v1", Namespace: "foo", Resource: "pods"}},
		{"/api/v1/namespaces/foo/pods/bar", APIPath{Version: "v1", Namespace: "foo", Resource: "pods", Name: "bar"}},
		{"/api/v1/namespaces/foo/pods/bar/log", APIPath{Version: "v1", Namespace: "foo", Resource: "pods", Name: "bar", Subresource: "log"}},
		{"/api/v1/namespaces/foo/pods/bar/exec", APIPath{Version: "v1", Namespace: "foo", Resource: "pods", Name: "bar", Subresource: "exec"}},
		{"/api/v1/nodes/n1", APIPath{Version: "v1", Resource: "nodes", Name: "n1"}},
		{"/apis/apps/v1/namespaces/foo/deployments", APIPath{Group: "apps", Version: "v1", Namespace: "foo", Resource: "deployments"}},
		{"/apis/apps/v1/deployments", APIPath{Group: "apps", Version: "v1", Resource: "deployments"}},
		{"/healthz", APIPath{}},
		{"/", APIPath{}},
		{"", APIPath{}},
		{"/api", APIPath{}},
		{"/apis", APIPath{}},
		{"/apis/apps", APIPath{}},
		{"/apis/apps/v1", APIPath{Group: "apps", Version: "v1"}},
		{"//api/v1/pods", APIPath{}},
		{"/API/v1/pods", APIPath{}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := parseAPIPath(tt.path)
			if got != tt.want {
				t.Errorf("parseAPIPath(%q) = %+v, want %+v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseResourceRule(t *testing.T) {
	tests := []struct {
		in      string
		want    ResourceRule
		wantErr bool
	}{
		{"*", ResourceRule{All: true}, false},
		{"configmaps", ResourceRule{Resource: "configmaps"}, false},
		{"apps/deployments", ResourceRule{Group: "apps", Resource: "deployments"}, false},
		{"  apps/deployments  ", ResourceRule{Group: "apps", Resource: "deployments"}, false},
		{"", ResourceRule{}, true},
		{"   ", ResourceRule{}, true},
		{"apps/", ResourceRule{}, true},
		{"/deployments", ResourceRule{}, true},
		{"a/b/c", ResourceRule{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseResourceRule(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseResourceRule(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestPolicy_Decide_StrictPreservesOriginal(t *testing.T) {
	p := PresetStrict()
	cases := []struct {
		name    string
		method  string
		path    string
		upgrade bool
		allowed bool
	}{
		{"GET allowed", "GET", "/api/v1/pods", false, true},
		{"DELETE blocked", "DELETE", "/api/v1/namespaces/foo/pods/bar", false, false},
		{"exec subresource blocked", "GET", "/api/v1/namespaces/foo/pods/bar/exec", true, false},
		{"exec subresource without upgrade also blocked", "POST", "/api/v1/namespaces/foo/pods/bar/exec", false, false},
		{"review POST allowed", "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", false, true},
		{"dryRun DELETE allowed", "DELETE", "/api/v1/namespaces/foo/pods/p1?dryRun=All", false, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.upgrade {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "SPDY/3.1")
			}
			_, ok := p.Decide(r)
			if ok != tt.allowed {
				t.Errorf("Decide() allowed=%v, want %v", ok, tt.allowed)
			}
		})
	}
}

func TestPolicy_Decide_ResourceAllowlist(t *testing.T) {
	p := Policy{
		Name: "test",
		AllowWriteResources: []ResourceRule{
			{Resource: "configmaps"},
			{Group: "apps", Resource: "deployments"},
		},
	}
	cases := []struct {
		name    string
		method  string
		path    string
		allowed bool
	}{
		{"configmap write allowed", "PATCH", "/api/v1/namespaces/foo/configmaps/cm1", true},
		{"deployment write allowed", "PUT", "/apis/apps/v1/namespaces/foo/deployments/d1", true},
		{"pod write blocked", "DELETE", "/api/v1/namespaces/foo/pods/p1", false},
		{"secret write blocked", "PATCH", "/api/v1/namespaces/foo/secrets/s1", false},
		{"cross-group same name blocked", "PATCH", "/apis/foo.io/v1/namespaces/foo/configmaps/cm1", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			_, ok := p.Decide(r)
			if ok != tt.allowed {
				t.Errorf("Decide() allowed=%v, want %v", ok, tt.allowed)
			}
		})
	}
}

func TestPolicy_Decide_NamespaceAllowlist(t *testing.T) {
	p := Policy{
		Name:                "ns",
		Namespaces:          []string{"dev", "staging"},
		AllowWriteResources: []ResourceRule{{All: true}},
	}
	cases := []struct {
		name    string
		method  string
		path    string
		allowed bool
	}{
		{"write in allowed ns", "DELETE", "/api/v1/namespaces/dev/pods/p1", true},
		{"write in disallowed ns", "DELETE", "/api/v1/namespaces/prod/pods/p1", false},
		{"read in disallowed ns still allowed", "GET", "/api/v1/namespaces/prod/pods", true},
		// The original bug: cluster-scoped writes silently bypassed the allowlist.
		{"cluster-scoped node write blocked when allowlist set", "PATCH", "/api/v1/nodes/n1", false},
		// The DELETE namespace bypass — Name interpreted as the namespace.
		{"delete allowed namespace", "DELETE", "/api/v1/namespaces/dev", true},
		{"delete disallowed namespace blocked", "DELETE", "/api/v1/namespaces/prod", false},
		// Cross-namespace deletecollection (no /namespaces/<ns>/) blocked.
		{"cross-ns deletecollection blocked", "DELETE", "/apis/apps/v1/deployments", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			_, ok := p.Decide(r)
			if ok != tt.allowed {
				t.Errorf("Decide() allowed=%v, want %v", ok, tt.allowed)
			}
		})
	}
}

func TestPolicy_Decide_NamespaceAllowlistAllowsClusterReads(t *testing.T) {
	p := Policy{
		Namespaces:          []string{"dev"},
		AllowWriteResources: []ResourceRule{{All: true}},
	}
	r := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	if _, ok := p.Decide(r); !ok {
		t.Error("cluster-scoped reads must remain allowed under namespace allowlist")
	}
}

func TestPolicy_Decide_UpgradeBypass_Codex(t *testing.T) {
	// Codex P1: a relaxed policy must NOT let an Upgrade header smuggle a
	// mutating request past the write check.
	p := PresetRelaxed()
	r := httptest.NewRequest("DELETE", "/api/v1/namespaces/foo/pods/p1", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "SPDY/3.1")
	if reason, ok := p.Decide(r); ok {
		t.Errorf("Upgrade header on non-upgrade path must be blocked even with AllowUpgrade; got allowed (reason=%q)", reason)
	}
}

func TestPolicy_Decide_UpgradeSubresources(t *testing.T) {
	cases := []struct {
		name         string
		allowUpgrade bool
		method       string
		path         string
		allowed      bool
	}{
		{"exec blocked when AllowUpgrade=false", false, "GET", "/api/v1/namespaces/foo/pods/bar/exec", false},
		{"exec allowed when AllowUpgrade=true", true, "GET", "/api/v1/namespaces/foo/pods/bar/exec", true},
		{"attach allowed when AllowUpgrade=true", true, "GET", "/api/v1/namespaces/foo/pods/bar/attach", true},
		{"portforward allowed when AllowUpgrade=true", true, "GET", "/api/v1/namespaces/foo/pods/bar/portforward", true},
		// pods/proxy: a sneaky tunneling subresource. Treated like an upgrade.
		{"proxy blocked when AllowUpgrade=false", false, "POST", "/api/v1/namespaces/foo/pods/bar/proxy", false},
		{"proxy allowed when AllowUpgrade=true", true, "POST", "/api/v1/namespaces/foo/pods/bar/proxy", true},
		// pods/eviction is a normal write — guarded by AllowWriteResources, not upgrade.
		{"eviction needs pods write rule", true, "POST", "/api/v1/namespaces/foo/pods/bar/eviction", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{AllowUpgrade: tt.allowUpgrade}
			r := httptest.NewRequest(tt.method, tt.path, nil)
			if _, ok := p.Decide(r); ok != tt.allowed {
				t.Errorf("Decide() allowed=%v, want %v", ok, tt.allowed)
			}
		})
	}
}

func TestPolicy_Decide_EvictionAllowedWithPodsRule(t *testing.T) {
	p := Policy{AllowWriteResources: []ResourceRule{{Resource: "pods"}}}
	r := httptest.NewRequest("POST", "/api/v1/namespaces/foo/pods/bar/eviction", nil)
	if _, ok := p.Decide(r); !ok {
		t.Error("eviction should be allowed when pods writes are allowed")
	}
}

func TestPresetByName(t *testing.T) {
	for _, name := range []string{"", "strict", "relaxed", "debug"} {
		if _, err := PresetByName(name); err != nil {
			t.Errorf("PresetByName(%q) returned error: %v", name, err)
		}
	}
	if _, err := PresetByName("bogus"); err == nil {
		t.Error("PresetByName(bogus) should fail")
	}
}

func TestIsUpgradeTokenization(t *testing.T) {
	cases := []struct {
		name       string
		connection string
		upgrade    string
		want       bool
	}{
		{"no headers", "", "", false},
		{"Connection: Upgrade", "Upgrade", "", true},
		{"Connection: keep-alive, Upgrade", "keep-alive, Upgrade", "", true},
		{"Connection: Upgrade,keep-alive", "Upgrade,keep-alive", "", true},
		{"Upgrade header only", "", "websocket", true},
		{"Connection: keep-alive only", "keep-alive", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.connection != "" {
				r.Header.Set("Connection", tt.connection)
			}
			if tt.upgrade != "" {
				r.Header.Set("Upgrade", tt.upgrade)
			}
			if got := isUpgrade(r); got != tt.want {
				t.Errorf("isUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_DenyReasonIncludesName(t *testing.T) {
	p := Policy{Name: "test-policy"}
	r := httptest.NewRequest("DELETE", "/api/v1/namespaces/foo/pods/p1", nil)
	reason, ok := p.Decide(r)
	if ok {
		t.Fatal("expected deny")
	}
	if !reflect.DeepEqual(reason, "DELETE on pods not allowed (policy test-policy)") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestPolicy_NoNameNoSuffix(t *testing.T) {
	// Anonymous policies (zero Name) should not emit a "(policy )" trailer.
	p := Policy{}
	r := httptest.NewRequest("DELETE", "/api/v1/namespaces/foo/pods/p1", nil)
	reason, _ := p.Decide(r)
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
	if reflect.DeepEqual(reason, "DELETE on pods not allowed (policy )") {
		t.Errorf("anonymous policy should not append empty policy name; got %q", reason)
	}
}
