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

### Readonly / policy proxy enforcement (`internal/proxy/`)

Despite the `-r` flag name, this is a general **policy-scoped shell** — readonly is just the strictest preset of a configurable `Policy`. The proxy intercepts every kubectl request and runs `Policy.Decide`. Files:

- `policy.go` — `Policy` value type with `Decide(r) (reason, allowed)`. Decide takes a value receiver — the zero value is equivalent to `PresetStrict`.
- `path.go` — `parseAPIPath` turns request paths into `{Group, Version, Namespace, Resource, Name, Subresource}`.
- `presets.go` — `PresetStrict`/`Relaxed`/`Debug`. `PresetByName("")` resolves to strict.
- `policyfile.go` — `LoadPolicyFile` uses `yaml.UnmarshalStrict` so unknown YAML fields are rejected. Resource tokens (`"configmaps"`, `"apps/deployments"`, `"*"`) parse via `ParseResourceRule`.
- `readonly.go` — `Start(Config)` runs the proxy with `Config.Policy` (zero value = strict). The handler delegates to `Policy.Decide` per request.

`Decide`'s evaluation order:

1. **Upgrade subresources** (`exec`/`attach`/`portforward`/`proxy`): require `AllowUpgrade=true` regardless of method. Then enforce namespace allowlist. Otherwise deny.
2. **Upgrade header on a non-upgrade path**: always deny, even when `AllowUpgrade=true`. (Closes a smuggling vector — `DELETE /pods/p1` with `Upgrade: foo` won't bypass the write check.)
3. **Safe methods** (`GET`/`HEAD`/`OPTIONS`): allow.
4. **Non-mutating POSTs** (SubjectAccessReview, TokenReview, etc.): regex-anchored to `authorization.k8s.io` / `authentication.k8s.io` API groups to prevent CRD spoofing.
5. **`?dryRun=All`**: allow.
6. **Unrecognized path** (`Resource == ""`): deny.
7. **Namespace allowlist** (if `Namespaces` is non-empty): the request's namespace must be in the list. For `namespaces/<name>` resource the `Name` is treated as the target namespace. Cluster-scoped or cross-namespace deletecollection paths (no `/namespaces/foo/` segment) are denied when a namespace allowlist is in effect.
8. **Resource allowlist** (`AllowWriteResources`): match by `ResourceRule{Group, Resource, All}`. Otherwise deny.

Set `DEBUG=1` (the env var is just `DEBUG`, not `KUBECTX_DEBUG`) to see proxy decisions on stderr (`[readonly-proxy] >> METHOD PATH -> proxied/405`). Server-loop errors are unconditionally logged with prefix `[kubectx readonly-proxy]`.

### Daemon / serve mode (`cmd/kubectx/serve.go`)

`kubectx --serve --advertise=host:port --kubeconfig-out=path ctx` runs the policy proxy without spawning a subshell, so a remote consumer (typically an agent in a sandbox container) can use it over a network. Key pieces:

- `proxy.GenerateSelfSignedTLS` (`tls.go`) — generates an ECDSA-P256 cert covering the advertise DNS/IP SANs. CAPEM is returned for embedding in the sandbox kubeconfig.
- `proxy.GenerateToken` + `withTokenAuth` (`auth.go`) — 256-bit random bearer token, constant-time comparison on each request. Wraps the policy handler so authn runs before policy.
- `proxy.EmitSandboxKubeconfig` (`kubeconfig_emit.go`) — builds the YAML the sandbox mounts.
- `proxy.Config` gains `ListenAddr`, `TLS`, `AuthToken`. When TLS is set, `srv.ServeTLS` is used; when `AuthToken` is non-empty, the handler is wrapped with auth.
- `ServeOp` (`cmd/kubectx/serve.go`) ties it together. Order of operations:
  1. `buildPolicy` from CLI flags
  2. validate `--kubeconfig-out`, resolve `--advertise` and `--listen` (loopback advertise → loopback default listen)
  3. `--no-tls` gate: refuse unless **both** listen host and advertise host are loopback
  4. `writeOriginalKubeconfigForProxy` (shells out to `kubectl config view --minify --flatten` into a 0600 temp file)
  5. `GenerateToken` + (when TLS) `GenerateSelfSignedTLS`
  6. `proxy.Start` (its own defense-in-depth check rejects non-loopback bind without TLS+AuthToken)
  7. `waitForProxyHandshake` — TCP for HTTP, full TLS handshake for HTTPS, so readiness reflects what the agent will actually do
  8. `EmitSandboxKubeconfig` + `writeKubeconfigOut` (0600 forced on a pre-existing path)
  9. block on signal; poll `proxy.Err()` for a crashed serve goroutine; graceful `Shutdown` on SIGINT/SIGTERM

`--listen` (bind address) and `--advertise` (host:port written into the sandbox kubeconfig) are separate because the host and sandbox see different networks. `--no-tls` is only accepted when `--advertise` resolves to loopback.

### Tests

- Go unit tests live next to the code (`flags_test.go`, `proxy/readonly_test.go`, etc.) and are table-driven.
- `internal/proxy/readonly_test.go` exercises `NewHandler` against an `httptest.NewServer` backend — extend it there when adding new allow/deny rules, not by writing integration tests.
- `test/*.bats` covers end-to-end CLI behavior with a fake kubeconfig fixture in `test/`.

### Releases

`.goreleaser.yml` cross-compiles both binaries for linux/darwin/windows × amd64/arm/arm64/ppc64le/s390x. Triggered by tags on `master`. Krew manifests live under `.krew/`.
