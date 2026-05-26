package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/fatih/color"

	"github.com/ahmetb/kubectx/internal/env"
	"github.com/ahmetb/kubectx/internal/printer"
	"github.com/ahmetb/kubectx/internal/proxy"
)

// InteractiveReadonlyShellOp launches fzf to pick a context, then starts a readonly shell.
type InteractiveReadonlyShellOp struct {
	SelfCmd     string
	PolicyFlags ReadonlyPolicyFlags
}

// ReadonlyShellOp starts a read-only sub-shell for a context.
type ReadonlyShellOp struct {
	Target      string
	PolicyFlags ReadonlyPolicyFlags
}

// ReadonlyPolicyFlags captures the policy-shaping flags accepted by the
// readonly shell and serve entry points. The zero value yields the strict
// default.
//
// Precedence (see buildPolicy):
//   - PolicyFile and Mode are mutually exclusive bases. If both are set,
//     buildPolicy errors out rather than silently picking one.
//   - AllowWrite, Namespaces and AllowExec layer on top of the chosen base.
//
// The Serve* fields are only consulted when --serve is also set; they
// describe how the daemon-mode proxy exposes itself to a sandbox.
type ReadonlyPolicyFlags struct {
	Mode       string
	PolicyFile string
	AllowWrite []string
	Namespaces []string
	AllowExec  bool

	Serve         bool
	Listen        string
	Advertise     string
	KubeconfigOut string
	NoTLS         bool
}

func (op InteractiveReadonlyShellOp) Run(_, stderr io.Writer) error {
	choice, err := fzfPickContext(op.SelfCmd, stderr)
	if err != nil || choice == "" {
		return err
	}
	return ReadonlyShellOp{Target: choice, PolicyFlags: op.PolicyFlags}.Run(nil, stderr)
}

func (op ReadonlyShellOp) Run(_, stderr io.Writer) error {
	policy, err := op.PolicyFlags.buildPolicy()
	if err != nil {
		return err
	}
	badgeColor := color.New(color.BgYellow, color.FgBlack, color.Bold)
	printer.EnableOrDisableColor(badgeColor)

	// badgeType is the kind of shell; badgeSuffix carries the policy name
	// when it's not pure readonly. Kept separate so the exit message can
	// place "EXITED" next to the type rather than after the policy name,
	// where it would read as part of the name (e.g. "relaxed EXITED").
	badgeType := "POLICY SHELL"
	badgeSuffix := ": " + policy.Name
	if !policy.AllowUpgrade && len(policy.AllowWriteResources) == 0 {
		badgeType = "READONLY SHELL"
		badgeSuffix = ""
	}

	s := &shellSession{
		target:   op.Target,
		extraEnv: []string{env.EnvReadonlyShell + "=1"},
		printEntry: func(w io.Writer, ctxName string) {
			fmt.Fprintf(w, "%s kubectl context is %s under policy %s — type 'exit' to leave.\n",
				badgeColor.Sprintf("[%s%s]", badgeType, badgeSuffix),
				printer.WarningColor.Sprint(ctxName),
				printer.WarningColor.Sprint(policy.Name))
		},
		printExit: func(w io.Writer, prevCtx string) {
			fmt.Fprintf(w, "%s kubectl context is now %s.\n",
				badgeColor.Sprintf("[%s EXITED%s]", badgeType, badgeSuffix),
				printer.WarningColor.Sprint(prevCtx))
		},
		transformKubeconfig: func(data []byte) ([]byte, func(), error) {
			// Write original kubeconfig to temp file for the proxy to load TLS/auth.
			origFile, err := os.CreateTemp("", "kubectx-readonly-orig-*.yaml")
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create temp kubeconfig file: %w", err)
			}
			origPath := origFile.Name()

			if _, err := origFile.Write(data); err != nil {
				origFile.Close()
				os.Remove(origPath)
				return nil, nil, fmt.Errorf("failed to write temp kubeconfig: %w", err)
			}
			origFile.Close()

			// Start the readonly proxy.
			p, err := proxy.Start(proxy.Config{
				KubeconfigPath: origPath,
				ContextName:    op.Target,
				Policy:         policy,
			})
			if err != nil {
				os.Remove(origPath)
				return nil, nil, fmt.Errorf("failed to start readonly proxy: %w", err)
			}

			// Rewrite kubeconfig to point to the proxy.
			rewritten, err := proxy.RewriteKubeconfig(data, p.Addr())
			if err != nil {
				p.Shutdown(context.Background())
				os.Remove(origPath)
				return nil, nil, fmt.Errorf("failed to rewrite kubeconfig: %w", err)
			}

			if err := waitForProxy(p.Addr(), 2*time.Second); err != nil {
				p.Shutdown(context.Background())
				os.Remove(origPath)
				return nil, nil, fmt.Errorf("readonly proxy did not become ready: %w", err)
			}

			cleanup := func() {
				p.Shutdown(context.Background())
				os.Remove(origPath)
			}
			return rewritten, cleanup, nil
		},
	}
	return s.run(stderr)
}

// waitForProxy blocks until the local proxy at addr accepts a TCP connection,
// or until budget elapses.
func waitForProxy(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s: %w", budget, lastErr)
}
