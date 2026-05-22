package main

import (
	"context"
	"fmt"
	"io"
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

// ReadonlyPolicyFlags captures the policy-shaping flags accepted by `-r`.
// All fields are optional; the zero value means "use the strict default".
type ReadonlyPolicyFlags struct {
	Mode       string   // --mode=strict|relaxed|debug
	PolicyFile string   // --policy=path/to/file.yaml
	AllowWrite []string // --allow-write=configmaps,apps/deployments
	Namespaces []string // --namespace=dev,staging
	AllowExec  bool     // --allow-exec
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

	s := &shellSession{
		target:   op.Target,
		extraEnv: []string{env.EnvReadonlyShell + "=1"},
		printEntry: func(w io.Writer, ctxName string) {
			fmt.Fprintf(w, "%s kubectl context is %s in READ-ONLY mode — type 'exit' to leave.\n",
				badgeColor.Sprint("[READONLY SHELL]"), printer.WarningColor.Sprint(ctxName))
		},
		printExit: func(w io.Writer, prevCtx string) {
			fmt.Fprintf(w, "%s kubectl context is now %s.\n",
				badgeColor.Sprint("[READONLY SHELL EXITED]"), printer.WarningColor.Sprint(prevCtx))
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

			time.Sleep(10 * time.Millisecond)

			cleanup := func() {
				p.Shutdown(context.Background())
				os.Remove(origPath)
			}
			return rewritten, cleanup, nil
		},
	}
	return s.run(stderr)
}
