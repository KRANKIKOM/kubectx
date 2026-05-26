package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestServeMode_TLSTokenPolicy starts a full TLS+token+policy proxy and
// drives it from a fake "kubectl" (an HTTP client) the way an agent
// container would. It verifies the three security layers stack:
//   - auth: requests without the token get 401
//   - policy: requests with the token but blocked by policy get 405
//   - happy path: GETs with the token are proxied through
func TestServeMode_TLSTokenPolicy(t *testing.T) {
	// Fake upstream apiserver.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"kind":"PodList"}`)
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)

	// Generate TLS + token.
	bundle, err := GenerateSelfSignedTLS(nil, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	// Build the proxy handler directly: relaxed-but-not-debug policy
	// (writes blocked, reads OK), wrapped with token auth, served over
	// TLS by httptest.
	policy := PresetStrict() // strict for this test
	handler := withTokenAuth(token, NewHandlerWithPolicy(target, http.DefaultTransport, policy))
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{bundle.Cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle.CAPEM) {
		t.Fatal("CAPEM did not parse")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	t.Run("missing token -> 401", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/pods")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("good token + GET -> 200", func(t *testing.T) {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/pods", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "PodList") {
			t.Errorf("body did not pass through: %s", body)
		}
	})

	t.Run("good token + DELETE -> 405 (policy)", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/namespaces/foo/pods/p1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405 (policy denied)", resp.StatusCode)
		}
	})

	t.Run("bad token + GET -> 401 (auth checked before policy)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/pods", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})
}
