package proxy

import (
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

func TestEmitSandboxKubeconfig_RoundTrip(t *testing.T) {
	bundle, err := GenerateSelfSignedTLS([]string{"host.docker.internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	yaml, err := EmitSandboxKubeconfig(
		"https://host.docker.internal:8443",
		"prod",
		"secret-token",
		bundle.CAPEM,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip through clientcmd so we know kubectl can read it.
	cfg, err := clientcmd.Load(yaml)
	if err != nil {
		t.Fatalf("kubectl cannot load emitted kubeconfig: %v", err)
	}
	if cfg.CurrentContext != "prod" {
		t.Errorf("current-context = %q, want prod", cfg.CurrentContext)
	}
	cluster := cfg.Clusters["prod"]
	if cluster == nil {
		t.Fatal("no cluster entry")
	}
	if cluster.Server != "https://host.docker.internal:8443" {
		t.Errorf("server = %q", cluster.Server)
	}
	if len(cluster.CertificateAuthorityData) == 0 {
		t.Error("CA data missing")
	}
	if cfg.AuthInfos["prod"].Token != "secret-token" {
		t.Errorf("token = %q", cfg.AuthInfos["prod"].Token)
	}

	// The CA must be the same bytes we passed in.
	if !strings.Contains(string(yaml), "certificate-authority-data") {
		t.Error("output missing certificate-authority-data")
	}
}

func TestEmitSandboxKubeconfig_RequiresAllFields(t *testing.T) {
	cases := map[string]struct {
		server, ctx, token, ca string
		wantErr                bool
	}{
		"no server":    {"", "p", "t", "ca", true},
		"no ctx":       {"https://x:1", "", "t", "ca", true},
		"no token":     {"https://x:1", "p", "", "ca", true},
		"empty ca ok":  {"http://x:1", "p", "t", "", false},
		"all provided": {"https://x:1", "p", "t", "ca", false},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := EmitSandboxKubeconfig(tt.server, tt.ctx, tt.token, []byte(tt.ca))
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

// EmitSandboxKubeconfig with empty caPEM must still round-trip cleanly
// through clientcmd.Load — the field should be omitted entirely, not
// emitted as an empty/placeholder.
func TestEmitSandboxKubeconfig_EmptyCARoundTrip(t *testing.T) {
	yaml, err := EmitSandboxKubeconfig("http://127.0.0.1:8443", "ctx", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Clusters["ctx"].CertificateAuthorityData) != 0 {
		t.Errorf("CA data should be empty, got %d bytes", len(cfg.Clusters["ctx"].CertificateAuthorityData))
	}
	if strings.Contains(string(yaml), "certificate-authority-data") {
		t.Errorf("yaml should not mention certificate-authority-data: %s", yaml)
	}
}
