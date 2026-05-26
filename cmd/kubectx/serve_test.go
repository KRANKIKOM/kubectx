package main

import (
	"strings"
	"testing"
)

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
