package main

import (
	"context"
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
type ServeOp struct {
	Target        string
	PolicyFlags   ReadonlyPolicyFlags
	Listen        string // bind address, e.g. "0.0.0.0:8443"
	Advertise     string // host[:port] written into the sandbox kubeconfig
	KubeconfigOut string // path to write the sandbox kubeconfig
	NoTLS         bool   // disable TLS (only valid for loopback)
}

func (op ServeOp) Run(stdout, stderr io.Writer) error {
	policy, err := op.PolicyFlags.buildPolicy()
	if err != nil {
		return err
	}
	if op.KubeconfigOut == "" {
		return fmt.Errorf("--kubeconfig-out is required for --serve")
	}

	listen, err := resolveListenAddr(op.Listen)
	if err != nil {
		return err
	}
	advertise, err := resolveAdvertise(op.Advertise, listen)
	if err != nil {
		return err
	}
	useTLS := !op.NoTLS
	if op.NoTLS && !isLoopback(advertise.Hostname()) {
		return fmt.Errorf("--no-tls is only allowed when --advertise is loopback (got %q)", advertise.Hostname())
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

	if err := waitForProxy(p.Addr(), 2*time.Second); err != nil {
		p.Shutdown(context.Background())
		return fmt.Errorf("proxy did not become ready: %w", err)
	}

	// Emit the sandbox kubeconfig.
	serverURL := scheme + "://" + advertise.Host
	caPEM := []byte{}
	if tlsBundle != nil {
		caPEM = tlsBundle.CAPEM
	} else {
		// Plaintext mode: the consumer doesn't need a CA, but the
		// kubeconfig emitter requires non-empty input. Use a placeholder
		// comment that won't be read because the URL is http://.
		caPEM = []byte("# proxy runs without TLS; CA not used\n")
	}
	out, err := proxy.EmitSandboxKubeconfig(serverURL, op.Target, token, caPEM)
	if err != nil {
		p.Shutdown(context.Background())
		return err
	}
	if err := os.WriteFile(op.KubeconfigOut, out, 0o600); err != nil {
		p.Shutdown(context.Background())
		return fmt.Errorf("write kubeconfig: %w", err)
	}

	fmt.Fprintf(stderr, "[kubectx policy serve] policy=%q listen=%s advertise=%s tls=%v\n",
		policy.Name, listen, advertise.Host, useTLS)
	fmt.Fprintf(stderr, "[kubectx policy serve] sandbox kubeconfig written to %s\n", op.KubeconfigOut)
	fmt.Fprintf(stderr, "[kubectx policy serve] ready — press Ctrl-C to stop\n")

	// Block on a signal so the proxy stays up for the agent.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(stderr, "[kubectx policy serve] shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.Shutdown(ctx)
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

func resolveListenAddr(listen string) (string, error) {
	if listen == "" {
		// Default to all interfaces so the sandbox bridge can reach it.
		return "0.0.0.0:0", nil
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return "", fmt.Errorf("--listen %q: %w", listen, err)
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

func isLoopback(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}
