package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// Policy describes which requests the readonly proxy should allow.
// The zero value blocks everything; use a preset (PresetStrict, etc.) or
// build one explicitly.
type Policy struct {
	// Name is used in debug logs and 405 error messages.
	Name string

	// AllowWriteResources is a list of "group/resource" tokens (or bare
	// "resource" for the core group) that may be mutated. e.g.
	// {"configmaps", "apps/deployments"}. "*" allows all.
	AllowWriteResources []string

	// Namespaces, if non-empty, restricts mutating operations to these
	// namespaces. Reads and cluster-scoped resources are unaffected so
	// `kubectl get nodes` still works.
	Namespaces []string

	// AllowUpgrade permits protocol upgrades — exec, cp, port-forward, attach.
	AllowUpgrade bool
}

// Decide returns ("", true) if the request is allowed, or (reason, false)
// if it should be blocked.
func (p *Policy) Decide(r *http.Request) (reason string, allowed bool) {
	if isUpgrade(r) {
		if !p.AllowUpgrade {
			return "exec/cp/port-forward are not allowed (policy " + p.Name + ")", false
		}
		if len(p.Namespaces) > 0 {
			info := parseAPIPath(r.URL.Path)
			if info.Namespace != "" && !contains(p.Namespaces, info.Namespace) {
				return fmt.Sprintf("namespace %q not in policy allowlist", info.Namespace), false
			}
		}
		return "", true
	}
	if isReadOnly(r) {
		return "", true
	}
	if isNonMutatingPost(r) {
		return "", true
	}
	if isDryRun(r) {
		return "", true
	}

	info := parseAPIPath(r.URL.Path)
	if info.Resource == "" {
		return fmt.Sprintf("%s requests are not allowed (policy %s)", r.Method, p.Name), false
	}

	if len(p.Namespaces) > 0 && info.Namespace != "" && !contains(p.Namespaces, info.Namespace) {
		return fmt.Sprintf("namespace %q not in policy allowlist", info.Namespace), false
	}

	if !p.allowsWrite(info) {
		return fmt.Sprintf("%s on %s not allowed (policy %s)", r.Method, resourceLabel(info), p.Name), false
	}
	return "", true
}

func (p *Policy) allowsWrite(info APIPath) bool {
	for _, tok := range p.AllowWriteResources {
		if tok == "*" {
			return true
		}
		grp, res, ok := strings.Cut(tok, "/")
		if !ok {
			// bare "resource" matches the core group
			if info.Group == "" && info.Resource == tok {
				return true
			}
			continue
		}
		if grp == info.Group && res == info.Resource {
			return true
		}
	}
	return false
}

func resourceLabel(info APIPath) string {
	if info.Group == "" {
		return info.Resource
	}
	return info.Group + "/" + info.Resource
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
