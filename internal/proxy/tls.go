package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ServerTLS bundles the artifacts a TLS-enabled proxy needs at startup
// plus the CA certificate the client kubeconfig must trust.
type ServerTLS struct {
	// Cert is the server certificate + private key, ready to load into
	// tls.Config.Certificates.
	Cert tls.Certificate
	// CAPEM is the PEM-encoded certificate the client must trust. For a
	// self-signed setup this is the server cert itself.
	CAPEM []byte
}

// GenerateSelfSignedTLS builds a fresh ECDSA-P256 self-signed certificate
// valid for one year covering the given DNS names and IPs. The returned
// CAPEM should be embedded in the sandbox kubeconfig.
func GenerateSelfSignedTLS(dnsNames []string, ips []net.IP) (ServerTLS, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ServerTLS{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return ServerTLS{}, fmt.Errorf("serial: %w", err)
	}

	now := time.Now()
	// Leaf certificate (not a CA). The sandbox kubeconfig embeds this
	// cert as its trust anchor, but the key is only used to sign TLS
	// handshakes — not to mint further certs. Keeping IsCA/CertSign off
	// limits the blast radius if the private key leaks.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "kubectx policy proxy"},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return ServerTLS{}, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return ServerTLS{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return ServerTLS{}, fmt.Errorf("load keypair: %w", err)
	}

	return ServerTLS{Cert: cert, CAPEM: certPEM}, nil
}
