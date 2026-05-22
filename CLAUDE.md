# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, Test, Lint

This is a Go project. There is no Makefile — operate via `go`/`bats`/`goreleaser` directly. CI definitions live in `.github/workflows/`.

```sh
# Build both binaries
go build ./cmd/kubectx
go build ./cmd/kubens

# Run all unit tests
go test ./...

# Run a single test (table-driven tests use t.Run subtests)
go test ./cmd/kubectx -run TestParseArgs
go test ./internal/proxy -run TestCheckRequest/upgrade_blocked

# Format + tidy checks (CI enforces both)
gofmt -s -d .
go mod tidy

# BATS integration tests (require a binary built first)
COMMAND=$(pwd)/kubectx bats test/kubectx.bats
COMMAND=$(pwd)/kubens  bats test/kubens.bats

# Release-style build locally
goreleaser release --snapshot --clean --skip=publish
```

The `kubectx` and `kubens` files checked into the repo root are *shell scripts* — the legacy implementation kept around for documentation/back-compat. The shipping binaries are the Go programs under `cmd/`.

## Architecture

Two CLIs (`cmd/kubectx`, `cmd/kubens`) share code through `internal/`. Each CLI follows the same dispatch pattern: `main.go` → `parseArgs(argv)` returns an `Op` interface value → `op.Run(stdout, stderr)` executes it. Adding a new flag means adding a new `Op` struct and a branch in `parseArgs`.

### Key internal packages

- `internal/kubeconfig/` — load, mutate, and save kubeconfig. All context/namespace manipulation goes through here, never directly via `client-go`.
- `internal/printer/` — colored output; honors `NO_COLOR` and `KUBECTX_CURRENT_{FG,BG}COLOR`.
- `internal/cmdutil/` — `IsInteractiveMode` (fzf gating), error helpers, deprecated-env warnings.
- `internal/env/` — string constants for env vars (`KUBECTX_READONLY_SHELL`, `KUBECTX_ISOLATED_SHELL`, `KUBECTX_IGNORE_FZF`, etc.). Add new env vars here, not as string literals at call sites.
- `internal/proxy/` — the readonly HTTP reverse proxy used by `kubectx -r`. See "Readonly shell" below.
- `internal/testutil/` — test scaffolding.

### Shell features (`-s` and `-r`)

Both spawn a subshell with a scoped `KUBECONFIG` pointing at a temp file containing only the selected context (extracted via `kubectl config view --minify --flatten`). The shared spawning logic lives in `cmd/kubectx/shell_session.go` (`shellSession.run`). `isolated_shell_guard.go` prevents nesting (`KUBECTX_ISOLATED_SHELL=1` is set inside the subshell and refused on re-entry).

- `-s` / `--shell` (`shell.go`): scope only. Subshell sees one context; writes still go to the real API server.
- `-r` / `--readonly` (`readonly_shell.go`): scope **plus** enforcement. Before spawning, it starts a localhost reverse proxy (`proxy.Start`) and rewrites the temp kubeconfig (`proxy.RewriteKubeconfig`) so the server URL points at `http://127.0.0.1:<random>` and cluster TLS/auth fields are stripped (auth happens inside the proxy via the original credentials). `KUBECTX_READONLY_SHELL=1` is informational — actual enforcement is HTTP-layer in the proxy.

### Readonly proxy enforcement (`internal/proxy/readonly.go`, `policy.go`)

Two layers:

1. **Fixed predicates** (`readonly.go`): `isUpgrade`, `isReadOnly`, `isNonMutatingPost` (anchored regex allowlist for `*Review` endpoints), `isDryRun`.
2. **Policy** (`policy.go`): user-shaped allow/deny rules — per-resource write allowlist, per-namespace scope, exec/upgrade toggle. Presets in `presets.go` (`strict` = original behavior; `relaxed`, `debug`). YAML loader in `policyfile.go`. CLI glue in `cmd/kubectx/readonly_policy.go` (flag parsing + `buildPolicy`).

`Policy.Decide` runs the fixed predicates first, then consults the allowlists for mutating methods. Namespace scoping gates **writes only** — reads and cluster-scoped resources are untouched so `kubectl get nodes` still works. `parseAPIPath` (`path.go`) turns request paths into `{Group, Version, Namespace, Resource, Name, Subresource}` for matching.

In order, `Decide` checks:
1. **Block protocol upgrades** (`Connection: Upgrade` / `Upgrade:` header), unless `Policy.AllowUpgrade` — this is what stops `kubectl exec`, `cp`, `port-forward`, `attach` (SPDY/WebSocket).
2. **Allow safe methods**: `GET`, `HEAD`, `OPTIONS`.
3. **Allow non-mutating POSTs** matching `nonMutatingPostPatterns` (SubjectAccessReview, TokenReview, SelfSubjectRulesReview, etc.) — these are POSTs by API design but don't persist resources. Patterns are anchored to the `authorization.k8s.io` / `authentication.k8s.io` API groups to prevent CRD spoofing.
4. **Allow `?dryRun=All`** queries.
5. Everything else returns `405 Method Not Allowed` with a `metav1.Status` body so `kubectl` prints a clean error.

Set `KUBECTX_DEBUG=1` to see proxy decisions on stderr (`[readonly-proxy] >> METHOD PATH -> proxied/405`).

### Tests

- Go unit tests live next to the code (`flags_test.go`, `proxy/readonly_test.go`, etc.) and are table-driven.
- `internal/proxy/readonly_test.go` exercises `NewHandler` against an `httptest.NewServer` backend — extend it there when adding new allow/deny rules, not by writing integration tests.
- `test/*.bats` covers end-to-end CLI behavior with a fake kubeconfig fixture in `test/`.

### Releases

`.goreleaser.yml` cross-compiles both binaries for linux/darwin/windows × amd64/arm/arm64/ppc64le/s390x. Triggered by tags on `master`. Krew manifests live under `.krew/`.
