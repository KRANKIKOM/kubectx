package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ahmetb/kubectx/internal/proxy"
)

// errTooManyReadonlyArgs is a sentinel so the caller can substitute the
// originally-typed trigger flag in the error message.
var errTooManyReadonlyArgs = errors.New("too many context arguments")

// isPolicyTrigger reports whether arg, appearing at argv[0], should route
// the command into policy-shell mode. `-r`/`--readonly` keeps the original
// entry point so existing invocations get strict mode by default; the
// other flags let callers enter policy-shell mode without `-r` at all.
func isPolicyTrigger(arg string) bool {
	if arg == "-r" || arg == "--readonly" {
		return true
	}
	key, _, _ := strings.Cut(arg, "=")
	switch key {
	case "--mode", "--policy", "--allow-write", "--namespace", "-n", "--allow-exec",
		"--serve", "--listen", "--advertise", "--kubeconfig-out", "--no-tls":
		return true
	}
	return false
}

// buildPolicy assembles a proxy.Policy from the CLI flags.
//
// Base policy:
//   - if --policy=<file> is given, the file is the base (and --mode is rejected)
//   - else --mode picks a preset (empty Mode resolves to "strict")
//
// Layered flags (--allow-write, --namespace, --allow-exec) extend the base.
//
// A zero-value flags struct still resolves to PresetStrict so callers get a
// named Policy for badge/log rendering.
func (f ReadonlyPolicyFlags) buildPolicy() (proxy.Policy, error) {
	if f.isZero() {
		return proxy.PresetStrict(), nil
	}
	if f.PolicyFile != "" && f.Mode != "" {
		return proxy.Policy{}, fmt.Errorf("--policy and --mode are mutually exclusive")
	}

	var p proxy.Policy
	var err error
	if f.PolicyFile != "" {
		p, err = proxy.LoadPolicyFile(f.PolicyFile)
	} else {
		p, err = proxy.PresetByName(f.Mode)
	}
	if err != nil {
		return proxy.Policy{}, err
	}

	var mods []string
	if f.AllowExec {
		p.AllowUpgrade = true
		mods = append(mods, "exec")
	}
	if len(f.AllowWrite) > 0 {
		extra, err := proxy.ParseResourceRules(f.AllowWrite)
		if err != nil {
			return proxy.Policy{}, fmt.Errorf("--allow-write: %w", err)
		}
		p.AllowWriteResources = append(p.AllowWriteResources, extra...)
		mods = append(mods, "writes")
	}
	if len(f.Namespaces) > 0 {
		p.Namespaces = append(p.Namespaces, f.Namespaces...)
		mods = append(mods, "ns")
	}
	if len(mods) > 0 {
		// Reflect customization in the policy name so the banner doesn't
		// say "strict" when exec or writes have been layered in.
		p.Name = p.Name + "+" + strings.Join(mods, ",")
	}
	return p, nil
}

func (f ReadonlyPolicyFlags) isZero() bool {
	return f.Mode == "" && f.PolicyFile == "" &&
		len(f.AllowWrite) == 0 && len(f.Namespaces) == 0 && !f.AllowExec
}

// serveOp builds a ServeOp from the parsed flags. ServeOp consumes the
// serve-mode fields through PolicyFlags — no need to duplicate them here.
func (f ReadonlyPolicyFlags) serveOp(target string) ServeOp {
	return ServeOp{Target: target, PolicyFlags: f}
}

// hasServeOnlyFlag reports whether any of the serve-mode flags were set.
// Used so the parser can flag misuses like `kubectx --listen=foo -r ctx`.
func (f ReadonlyPolicyFlags) hasServeOnlyFlag() bool {
	return f.Listen != "" || f.Advertise != "" || f.KubeconfigOut != "" || f.NoTLS
}

// parseReadonlyFlags scans argv (the args *after* `-r`/`--readonly`, or the
// full argv when invoked via a bare policy flag) and pulls out policy flags
// plus the positional context name. Flags may appear before or after the
// context name.
func parseReadonlyFlags(argv []string) (target string, flags ReadonlyPolicyFlags, err error) {
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		key, val, hasEq := strings.Cut(arg, "=")

		take := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(argv) {
				return "", fmt.Errorf("flag %s needs a value", key)
			}
			i++
			return argv[i], nil
		}

		switch key {
		case "--mode":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.Mode = v
		case "--policy":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.PolicyFile = v
		case "--allow-write":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.AllowWrite = append(flags.AllowWrite, splitCSV(v)...)
		case "--namespace", "-n":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.Namespaces = append(flags.Namespaces, splitCSV(v)...)
		case "--allow-exec":
			if hasEq {
				return "", flags, fmt.Errorf("--allow-exec does not take a value")
			}
			flags.AllowExec = true
		case "--serve":
			if hasEq {
				return "", flags, fmt.Errorf("--serve does not take a value")
			}
			flags.Serve = true
		case "--listen":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.Listen = v
		case "--advertise":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.Advertise = v
		case "--kubeconfig-out":
			v, e := take()
			if e != nil {
				return "", flags, e
			}
			flags.KubeconfigOut = v
		case "--no-tls":
			if hasEq {
				return "", flags, fmt.Errorf("--no-tls does not take a value")
			}
			flags.NoTLS = true
		default:
			if strings.HasPrefix(arg, "-") {
				return "", flags, fmt.Errorf("unknown policy flag: %s", arg)
			}
			if target != "" {
				return "", flags, errTooManyReadonlyArgs
			}
			target = arg
		}
	}
	return target, flags, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
