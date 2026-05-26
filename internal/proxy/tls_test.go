package proxy

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestGenerateSelfSignedTLS(t *testing.T) {
	bundle, err := GenerateSelfSignedTLS(
		[]string{"host.docker.internal"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.17.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Cert.Certificate) == 0 {
		t.Fatal("no cert in bundle")
	}
	parsed, err := x509.ParseCertificate(bundle.Cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(parsed.DNSNames, "host.docker.internal") {
		t.Errorf("cert missing DNS SAN: %v", parsed.DNSNames)
	}
	if !containsIP(parsed.IPAddresses, "127.0.0.1") {
		t.Errorf("cert missing IP SAN 127.0.0.1: %v", parsed.IPAddresses)
	}
	if !containsIP(parsed.IPAddresses, "172.17.0.1") {
		t.Errorf("cert missing IP SAN 172.17.0.1: %v", parsed.IPAddresses)
	}
	if len(bundle.CAPEM) == 0 {
		t.Error("CAPEM is empty")
	}

	// CAPEM should be loadable as a trust anchor.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle.CAPEM) {
		t.Error("CAPEM did not parse as a cert pool")
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func containsIP(haystack []net.IP, needle string) bool {
	want := net.ParseIP(needle)
	for _, ip := range haystack {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}
