// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ahmetb/kubectx/internal/cmdutil"
)

// UnsupportedOp indicates an unsupported flag.
type UnsupportedOp struct{ Err error }

func (op UnsupportedOp) Run(_, _ io.Writer) error {
	return op.Err
}

// triggerLabel strips =value from a flag so error messages quote the flag
// alone (`'--mode' accepts ...`) rather than echoing the user's value.
func triggerLabel(arg string) string {
	if i := strings.Index(arg, "="); i >= 0 {
		return arg[:i]
	}
	return arg
}

// parseArgs looks at flags (excl. executable name, i.e. argv[0])
// and decides which operation should be taken.
func parseArgs(argv []string) Op {
	if len(argv) == 0 {
		if cmdutil.IsInteractiveMode(os.Stdout) {
			return InteractiveSwitchOp{SelfCmd: os.Args[0]}
		}
		return ListOp{}
	}

	// Any of these at argv[0] triggers policy-shell mode. `-r`/`--readonly`
	// keeps the original entry point so existing invocations get the strict
	// default; the others let callers enter policy-shell mode without `-r`.
	if isPolicyTrigger(argv[0]) {
		rest := argv
		trigger := triggerLabel(argv[0])
		if argv[0] == "-r" || argv[0] == "--readonly" {
			rest = argv[1:]
		}
		target, flags, err := parseReadonlyFlags(rest)
		if err != nil {
			if errors.Is(err, errTooManyReadonlyArgs) {
				return UnsupportedOp{Err: fmt.Errorf("'%s' accepts at most one context name argument", trigger)}
			}
			return UnsupportedOp{Err: err}
		}
		if flags.Serve {
			if target == "" {
				return UnsupportedOp{Err: fmt.Errorf("--serve requires a context name argument")}
			}
			return flags.serveOp(target)
		}
		if flags.hasServeOnlyFlag() {
			return UnsupportedOp{Err: fmt.Errorf("--listen/--advertise/--kubeconfig-out/--no-tls require --serve (add --serve to enable daemon mode)")}
		}
		if target == "" {
			if cmdutil.IsInteractiveMode(os.Stdout) {
				return InteractiveReadonlyShellOp{SelfCmd: os.Args[0], PolicyFlags: flags}
			}
			return UnsupportedOp{Err: fmt.Errorf("'%s' requires a context name argument (or fzf for interactive mode)", trigger)}
		}
		return ReadonlyShellOp{Target: target, PolicyFlags: flags}
	}

	if argv[0] == "--shell" || argv[0] == "-s" {
		if len(argv) == 1 {
			if cmdutil.IsInteractiveMode(os.Stdout) {
				return InteractiveShellOp{SelfCmd: os.Args[0]}
			}
			return UnsupportedOp{Err: fmt.Errorf("'%s' requires a context name argument (or fzf for interactive mode)", argv[0])}
		}
		if len(argv) == 2 {
			return ShellOp{Target: argv[1]}
		}
		return UnsupportedOp{Err: fmt.Errorf("'%s' accepts at most one context name argument", argv[0])}
	}

	if argv[0] == "-d" {
		if len(argv) == 1 {
			if cmdutil.IsInteractiveMode(os.Stdout) {
				return InteractiveDeleteOp{SelfCmd: os.Args[0]}
			} else {
				return UnsupportedOp{Err: fmt.Errorf("'-d' needs arguments")}
			}
		}
		return DeleteOp{Contexts: argv[1:]}
	}

	if len(argv) == 1 {
		v := argv[0]
		if v == "--help" || v == "-h" {
			return HelpOp{}
		}
		if v == "--version" || v == "-V" {
			return VersionOp{}
		}
		if v == "--current" || v == "-c" {
			return CurrentOp{}
		}
		if v == "--unset" || v == "-u" {
			return UnsetOp{}
		}

		if new, old, ok := parseRenameSyntax(v); ok {
			return RenameOp{New: new, Old: old}
		}

		if strings.HasPrefix(v, "-") && v != "-" {
			return UnsupportedOp{Err: fmt.Errorf("unsupported option '%s'", v)}
		}
		return SwitchOp{Target: argv[0]}
	}
	return UnsupportedOp{Err: fmt.Errorf("too many arguments")}
}
