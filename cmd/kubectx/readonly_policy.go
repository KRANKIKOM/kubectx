package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ahmetb/kubectx/internal/proxy"
)

// errTooManyReadonlyArgs is a sentinel so the caller can replace
// the literal "-r"/"--readonly" in the message.
var errTooManyReadonlyArgs = errors.New("too many context arguments")

// buildPolicy assembles a *proxy.Policy from the CLI flags. Precedence:
//
//  1. start from --mode preset (default "strict")
//  2. layer --policy=<file> on top, fully replacing the preset
//  3. apply individual flags (--allow-write, --namespace, --allow-exec)
//     as additions to whatever we have so far
//
// A nil return means "use the strict default" — proxy.Start handles that.
func (f ReadonlyPolicyFlags) buildPolicy() (*proxy.Policy, error) {
	if f.isZero() {
		return nil, nil
	}

	var p *proxy.Policy
	if f.PolicyFile != "" {
		var err error
		p, err = proxy.LoadPolicyFile(f.PolicyFile)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		p, err = proxy.PresetByName(f.Mode)
		if err != nil {
			return nil, err
		}
	}

	if f.AllowExec {
		p.AllowUpgrade = true
	}
	if len(f.AllowWrite) > 0 {
		p.AllowWriteResources = append(p.AllowWriteResources, f.AllowWrite...)
	}
	if len(f.Namespaces) > 0 {
		p.Namespaces = append(p.Namespaces, f.Namespaces...)
	}
	return p, nil
}

// parseReadonlyFlags scans argv (the args *after* `-r`/`--readonly`) and
// pulls out policy flags plus the positional context name. Flags may
// appear before or after the context name.
//
// Returns the context name ("" if not provided) and the parsed flags.
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

func (f ReadonlyPolicyFlags) isZero() bool {
	return f.Mode == "" && f.PolicyFile == "" &&
		len(f.AllowWrite) == 0 && len(f.Namespaces) == 0 && !f.AllowExec
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
