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
	case "--mode", "--policy", "--allow-write", "--namespace", "-n", "--allow-exec":
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

	if f.AllowExec {
		p.AllowUpgrade = true
	}
	if len(f.AllowWrite) > 0 {
		extra, err := proxy.ParseResourceRules(f.AllowWrite)
		if err != nil {
			return proxy.Policy{}, fmt.Errorf("--allow-write: %w", err)
		}
		p.AllowWriteResources = append(p.AllowWriteResources, extra...)
	}
	if len(f.Namespaces) > 0 {
		p.Namespaces = append(p.Namespaces, f.Namespaces...)
	}
	return p, nil
}

func (f ReadonlyPolicyFlags) isZero() bool {
	return f.Mode == "" && f.PolicyFile == "" &&
		len(f.AllowWrite) == 0 && len(f.Namespaces) == 0 && !f.AllowExec
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
		default:
			if strings.HasPrefix(arg, "-") {
				return "", flags, fmt.Errorf("unknown flag for -r: %s", arg)
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
