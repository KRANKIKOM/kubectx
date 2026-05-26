package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ahmetb/kubectx/internal/proxy"
)

// ServeOp runs the policy proxy as a daemon so a remote consumer
// (e.g. an agent in a sandbox container) can reach it over a network.
//
// Unlike ReadonlyShellOp, ServeOp does not spawn a subshell. It writes
// a sandbox-facing kubeconfig and blocks until SIGINT/SIGTERM.
//
// The serve-mode flags (--listen, --advertise, --kubeconfig-out,
// --no-tls) live on PolicyFlags alongside the policy-shaping flags;
// ServeOp reads them through PolicyFlags so there is one source of truth.
type ServeOp struct {
	Target      string
	PolicyFlags ReadonlyPolicyFlags
}

func (op ServeOp) Run(stdout, stderr io.Writer) error {
	policy, err := op.PolicyFlags.buildPolicy()
	if err != nil {
		return err
	}
	flags := op.PolicyFlags
	if flags.KubeconfigOut == "" {
		return fmt.Errorf("--kubeconfig-out is required for --serve (path where the sandbox kubeconfig will be written)")
	}

	// Resolve advertise first so we can pick a sensible default for listen.
	// If the user is advertising a loopback hostname, default listen to
	// 127.0.0.1 (more secure). Only fall back to 0.0.0.0 when advertise is
	// explicitly non-loopback.
	advertise, err := resolveAdvertise(flags.Advertise, flags.Listen)
	if err != nil {
		return err
	}
	listen, err := resolveListenAddr(flags.Listen, advertise)
	if err != nil {
		return err
	}
	useTLS := !flags.NoTLS
	if err := checkNoTLS(flags.NoTLS, listen, advertise); err != nil {
		return err
	}

	// Write the original kubeconfig to a temp file the proxy can load
	// TLS/auth from. This mirrors what readonly_shell.go does.
	origPath, cleanupOrig, err := writeOriginalKubeconfigForProxy(op.Target)
	if err != nil {
		return err
	}
	defer cleanupOrig()

	token, err := proxy.GenerateToken()
	if err != nil {
		return err
	}

	var tlsBundle *proxy.ServerTLS
	scheme := "http"
	if useTLS {
		bundle, err := proxy.GenerateSelfSignedTLS(
			tlsSANNames(advertise.Hostname()),
			tlsSANIPs(advertise.Hostname()),
		)
		if err != nil {
			return fmt.Errorf("generate TLS: %w", err)
		}
		tlsBundle = &bundle
		scheme = "https"
	}

	p, err := proxy.Start(proxy.Config{
		KubeconfigPath: origPath,
		ContextName:    op.Target,
		Policy:         policy,
		ListenAddr:     listen,
		TLS:            tlsBundle,
		AuthToken:      token,
	})
	if err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}

	var tlsProbe *tls.Config
	if tlsBundle != nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(tlsBundle.CAPEM)
		tlsProbe = &tls.Config{RootCAs: pool, ServerName: advertise.Hostname()}
	}
	if err := waitForProxyHandshake(p.Addr(), 2*time.Second, tlsProbe); err != nil {
		shutdown(p)
		return fmt.Errorf("proxy did not become ready: %w", err)
	}

	// Emit the sandbox kubeconfig.
	serverURL := scheme + "://" + advertise.Host
	var caPEM []byte
	if tlsBundle != nil {
		caPEM = tlsBundle.CAPEM
	}
	out, err := proxy.EmitSandboxKubeconfig(serverURL, op.Target, token, caPEM)
	if err != nil {
		shutdown(p)
		return err
	}
	if err := writeKubeconfigOut(flags.KubeconfigOut, out); err != nil {
		shutdown(p)
		return err
	}

	fmt.Fprintf(stderr, "[kubectx policy serve] policy=%q listen=%s advertise=%s tls=%v\n",
		policy.Name, listen, advertise.Host, useTLS)
	fmt.Fprintf(stderr, "[kubectx policy serve] sandbox kubeconfig written to %s\n", flags.KubeconfigOut)
	fmt.Fprintf(stderr, "[kubectx policy serve] ready — press Ctrl-C to stop\n")

	// Block on a signal so the proxy stays up for the agent. Poll the
	// serve goroutine's exit channel too, so a crashed proxy surfaces as
	// a non-zero exit instead of a silently-dead daemon.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sig:
			fmt.Fprintln(stderr, "[kubectx policy serve] shutting down")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return p.Shutdown(ctx)
		case <-ticker.C:
			if err := p.Err(); err != nil {
				return fmt.Errorf("proxy died: %w", err)
			}
		}
	}
}

// checkNoTLS enforces the safety constraint that --no-tls requires
// BOTH the listen host AND the advertise host to be loopback. Either
// alone is insufficient: listen=0.0.0.0 + advertise=localhost would
// expose plaintext on the network, while listen=127.0.0.1 +
// advertise=hostX makes the emitted kubeconfig unreachable.
func checkNoTLS(noTLS bool, listen string, advertise *url.URL) error {
	if !noTLS {
		return nil
	}
	listenHost, _, _ := net.SplitHostPort(listen)
	if !isLoopback(listenHost) {
		return fmt.Errorf("--no-tls requires --listen to bind on loopback (got %q); the proxy would otherwise serve a bearer token in plaintext over the network", listenHost)
	}
	if !isLoopback(advertise.Hostname()) {
		return fmt.Errorf("--no-tls is only allowed when --advertise is loopback (got %q)", advertise.Hostname())
	}
	return nil
}

// writeKubeconfigOut writes the emitted sandbox kubeconfig to path with
// mode 0600. Unlike os.WriteFile, this explicitly chmods after writing so
// a pre-existing file with looser permissions gets tightened to match the
// fresh bearer-token-bearing contents.
func writeKubeconfigOut(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open kubeconfig %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write kubeconfig %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod kubeconfig %s: %w", path, err)
	}
	return nil
}

// shutdown stops the proxy with a bounded timeout. Failure-path callers
// can't afford to block indefinitely on Shutdown if an upstream connection
// is hung.
func shutdown(p *proxy.ReadonlyProxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.Shutdown(ctx)
}

// writeOriginalKubeconfigForProxy minifies the current kubeconfig down to
// the target context and writes it to a temp file. Returned cleanup
// removes the temp file.
func writeOriginalKubeconfigForProxy(target string) (string, func(), error) {
	out, err := exec.Command("kubectl", "config", "view", "--minify", "--flatten", "--context", target).Output()
	if err != nil {
		return "", nil, fmt.Errorf("kubectl config view: %w", err)
	}
	f, err := os.CreateTemp("", "kubectx-serve-orig-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("temp file: %w", err)
	}
	path := f.Name()
	if _, err := f.Write(out); err != nil {
		f.Close()
		os.Remove(path)
		return "", nil, fmt.Errorf("write temp file: %w", err)
	}
	f.Close()
	return path, func() { os.Remove(path) }, nil
}

func resolveListenAddr(listen string, advertise *url.URL) (string, error) {
	if listen == "" {
		// Default to 0.0.0.0 only when advertise is non-loopback (the user
		// wants to be reachable from another network namespace). For
		// loopback advertise, stay on 127.0.0.1 — same blast radius as
		// the legacy `-r` shell mode.
		host := "127.0.0.1"
		if !isLoopback(advertise.Hostname()) {
			host = "0.0.0.0"
		}
		_, port, _ := net.SplitHostPort(advertise.Host)
		return net.JoinHostPort(host, port), nil
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return "", fmt.Errorf("--listen %q: %w (expected host:port, e.g. 0.0.0.0:8443)", listen, err)
	}
	return listen, nil
}

// resolveAdvertise turns the user-supplied --advertise into a URL whose
// Host field carries `host[:port]`. If port is omitted, it's borrowed
// from the listener.
func resolveAdvertise(advertise, listen string) (*url.URL, error) {
	if advertise == "" {
		return nil, fmt.Errorf("--advertise is required (the host:port the sandbox will dial)")
	}
	host, port, err := net.SplitHostPort(advertise)
	if err != nil {
		// No port — take it from listen.
		_, listenPort, lerr := net.SplitHostPort(listen)
		if lerr != nil {
			return nil, fmt.Errorf("--advertise %q has no port and --listen %q has no port either", advertise, listen)
		}
		host = advertise
		port = listenPort
	}
	if host == "" {
		return nil, fmt.Errorf("--advertise must include a hostname the sandbox can dial (got %q)", advertise)
	}
	if port == "0" {
		return nil, fmt.Errorf("--advertise must use a fixed port; pick one via --listen=host:PORT")
	}
	u := &url.URL{Host: net.JoinHostPort(host, port)}
	return u, nil
}

func tlsSANNames(host string) []string {
	if net.ParseIP(host) == nil && host != "" {
		return []string{host}
	}
	return nil
}

func tlsSANIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	return nil
}

// isLoopback reports whether host resolves to a loopback address. An
// empty host is NOT treated as loopback — `--advertise=:8443` with an
// empty host would let `--no-tls` slip past the safety check while the
// proxy is actually bound on 0.0.0.0.
func isLoopback(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
