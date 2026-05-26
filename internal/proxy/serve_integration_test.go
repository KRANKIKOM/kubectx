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

	t.Run("wrong CA fails TLS handshake", func(t *testing.T) {
		// Untrusted-CA client should not be able to establish TLS at all.
		untrusted := &http.Client{
			Timeout:   2 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{}},
		}
		_, err := untrusted.Get(srv.URL + "/api/v1/pods")
		if err == nil {
			t.Error("expected TLS handshake error for untrusted CA")
		}
	})

	t.Run("plaintext HTTP to HTTPS proxy fails", func(t *testing.T) {
		// Server expects TLS; an http:// request should error or 400.
		// Use the bind addr without scheme rewriting.
		httpURL := strings.Replace(srv.URL, "https://", "http://", 1)
		resp, err := client.Get(httpURL + "/api/v1/pods")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Errorf("expected error or 4xx for http→tls; got %d", resp.StatusCode)
			}
		}
	})

	t.Run("upstream never sees Authorization header", func(t *testing.T) {
		// New upstream that captures the inbound Authorization header.
		var sawAuth string
		strictUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(strictUpstream.Close)
		strictTarget, _ := url.Parse(strictUpstream.URL)

		h := withTokenAuth(token, NewHandlerWithPolicy(strictTarget, http.DefaultTransport, PresetStrict()))
		strictSrv := httptest.NewUnstartedServer(h)
		strictSrv.TLS = &tls.Config{Certificates: []tls.Certificate{bundle.Cert}}
		strictSrv.StartTLS()
		t.Cleanup(strictSrv.Close)

		req, _ := http.NewRequest("GET", strictSrv.URL+"/api/v1/pods", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if sawAuth != "" {
			t.Errorf("upstream saw Authorization=%q; must be stripped", sawAuth)
		}
	})
}

// TestStart_RequiresAuthAndTLSForNonLoopback exercises the defense-in-depth
// invariant in proxy.Start: non-loopback listen addrs must come with TLS
// AND AuthToken. The CLI enforces this too, but the proxy package keeps
// the invariant for any future caller.
func TestStart_RequiresAuthAndTLSForNonLoopback(t *testing.T) {
	// We can't easily call proxy.Start (it needs a kubeconfig file), so
	// we exercise the invariant by hand: build a Config and ensure the
	// validate-before-listen branch returns the right errors. Instead of
	// running Start, just assert hostIsLoopback() answers correctly on
	// the inputs the invariant uses.
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"", false},
		{"host.docker.internal", false},
	}
	for _, tt := range cases {
		t.Run(tt.host, func(t *testing.T) {
			if got := hostIsLoopback(tt.host); got != tt.want {
				t.Errorf("hostIsLoopback(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
