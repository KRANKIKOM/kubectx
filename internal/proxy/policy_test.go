package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAPIPath(t *testing.T) {
	tests := []struct {
		path string
		want APIPath
	}{
		{"/api/v1/pods", APIPath{Version: "v1", Resource: "pods"}},
		{"/api/v1/namespaces/foo/pods", APIPath{Version: "v1", Namespace: "foo", Resource: "pods"}},
		{"/api/v1/namespaces/foo/pods/bar", APIPath{Version: "v1", Namespace: "foo", Resource: "pods", Name: "bar"}},
		{"/api/v1/namespaces/foo/pods/bar/log", APIPath{Version: "v1", Namespace: "foo", Resource: "pods", Name: "bar", Subresource: "log"}},
		{"/api/v1/namespaces/foo", APIPath{Version: "v1", Resource: "namespaces", Name: "foo"}},
		{"/api/v1/nodes/n1", APIPath{Version: "v1", Resource: "nodes", Name: "n1"}},
		{"/apis/apps/v1/namespaces/foo/deployments", APIPath{Group: "apps", Version: "v1", Namespace: "foo", Resource: "deployments"}},
		{"/apis/apps/v1/deployments", APIPath{Group: "apps", Version: "v1", Resource: "deployments"}},
		{"/healthz", APIPath{}},
		{"/", APIPath{}},
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

func TestPolicy_Decide_Strict(t *testing.T) {
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
		{"exec blocked", "GET", "/api/v1/namespaces/foo/pods/bar/exec", true, false},
		{"review POST allowed", "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", false, true},
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
	p := &Policy{
		Name:                "test",
		AllowWriteResources: []string{"configmaps", "apps/deployments"},
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

func TestPolicy_Decide_Namespaces(t *testing.T) {
	p := &Policy{
		Name:                "ns",
		Namespaces:          []string{"dev", "staging"},
		AllowWriteResources: []string{"*"},
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
		{"cluster-scoped write (e.g. nodes) allowed when ns empty", "PATCH", "/api/v1/nodes/n1", true},
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

func TestPolicy_Decide_AllowUpgrade(t *testing.T) {
	p := PresetRelaxed()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/foo/pods/bar/exec", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "SPDY/3.1")
	if _, ok := p.Decide(r); !ok {
		t.Error("PresetRelaxed should allow exec")
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
