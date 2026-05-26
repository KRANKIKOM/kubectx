package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKubeconfigOut must always end with mode 0600 — even if the path
// already existed with a looser mode. os.WriteFile alone wouldn't:
// O_CREATE only applies the mode on creation, leaving an existing 0644
// file (or worse, a world-readable one with a stale token) at 0644.
func TestWriteKubeconfigOut_TightensExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kc.yaml")
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeKubeconfigOut(path, []byte("fresh-token: yes\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %#o, want 0600 (file must be tightened to protect bearer token)", got)
	}
}

func TestWriteKubeconfigOut_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.yaml")
	if err := writeKubeconfigOut(path, []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %#o, want 0600", got)
	}
}

func TestCheckNoTLS(t *testing.T) {
	cases := []struct {
		name      string
		noTLS     bool
		listen    string
		advertise string
		wantErr   string
	}{
		{"TLS on always allowed", false, "0.0.0.0:8443", "host.docker.internal:8443", ""},
		{"loopback listen + loopback advertise ok", true, "127.0.0.1:8443", "localhost:8443", ""},
		{"non-loopback listen rejected", true, "0.0.0.0:8443", "localhost:8443", "--no-tls requires --listen to bind on loopback"},
		{"non-loopback advertise rejected", true, "127.0.0.1:8443", "host.docker.internal:8443", "--no-tls is only allowed when --advertise is loopback"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			adv := &url.URL{Host: tt.advertise}
			err := checkNoTLS(tt.noTLS, tt.listen, adv)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"", false}, // empty != loopback, so --no-tls can't slip past
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"127.0.0.5", true},
		{"::1", true},
		{"0.0.0.0", false}, // all-interfaces, not loopback
		{"host.docker.internal", false},
		{"172.17.0.1", false},
	}
	for _, tt := range cases {
		t.Run(tt.host, func(t *testing.T) {
			if got := isLoopback(tt.host); got != tt.want {
				t.Errorf("isLoopback(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestResolveListenAddr(t *testing.T) {
	cases := []struct {
		name      string
		listen    string
		advertise string // host:port
		want      string
		wantErr   string
	}{
		{"empty + loopback advertise -> 127.0.0.1", "", "localhost:8443", "127.0.0.1:8443", ""},
		{"empty + non-loopback advertise -> 0.0.0.0", "", "host.docker.internal:8443", "0.0.0.0:8443", ""},
		{"explicit listen preserved", "0.0.0.0:9999", "host.docker.internal:8443", "0.0.0.0:9999", ""},
		{"invalid listen errors", "not-a-host-port", "host:8443", "", "expected host:port"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			adv := &url.URL{Host: tt.advertise}
			got, err := resolveListenAddr(tt.listen, adv)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want contains %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveAdvertise(t *testing.T) {
	cases := []struct {
		name      string
		advertise string
		listen    string
		wantHost  string
		wantErr   string
	}{
		{"explicit host:port", "host.docker.internal:8443", "0.0.0.0:8443", "host.docker.internal:8443", ""},
		{"borrows port from listen", "host.docker.internal", "0.0.0.0:8443", "host.docker.internal:8443", ""},
		{"empty advertise errors", "", "0.0.0.0:8443", "", "--advertise is required"},
		{"empty host with port errors", ":8443", "0.0.0.0:8443", "", "--advertise must include a hostname"},
		{"port 0 errors", "host:0", "0.0.0.0:0", "", "must use a fixed port"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			u, err := resolveAdvertise(tt.advertise, tt.listen)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if u.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", u.Host, tt.wantHost)
			}
		})
	}
}
