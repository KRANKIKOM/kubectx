package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// upgradeSubresources is the set of pod subresources that legitimately use
// protocol upgrades (SPDY/WebSocket) and would let a client tunnel arbitrary
// traffic past HTTP-method filtering. Treated as a single class gated by
// Policy.AllowUpgrade regardless of method.
var upgradeSubresources = map[string]struct{}{
	"exec":        {},
	"attach":      {},
	"portforward": {},
	"proxy":       {},
}

// ResourceRule allows writes on a specific (group, resource).
// Use ParseResourceRule to construct from string form ("configmaps",
// "apps/deployments", "*").
type ResourceRule struct {
	Group    string
	Resource string
	All      bool // matches every resource (the "*" form)
}

// ParseResourceRules runs ParseResourceRule over each token, surfacing
// parse errors at config-load time so typos don't reach the request path.
func ParseResourceRules(tokens []string) ([]ResourceRule, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	rules := make([]ResourceRule, 0, len(tokens))
	for _, t := range tokens {
		r, err := ParseResourceRule(t)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// ParseResourceRule parses a token of the form "*", "resource", or
// "group/resource". Empty or malformed tokens return an error.
func ParseResourceRule(s string) (ResourceRule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ResourceRule{}, fmt.Errorf("resource rule is empty")
	}
	if s == "*" {
		return ResourceRule{All: true}, nil
	}
	grp, res, ok := strings.Cut(s, "/")
	if !ok {
		return ResourceRule{Group: "", Resource: grp}, nil
	}
	if grp == "" || res == "" || strings.Contains(res, "/") {
		return ResourceRule{}, fmt.Errorf("resource rule %q: expected '<resource>' or '<group>/<resource>'", s)
	}
	return ResourceRule{Group: grp, Resource: res}, nil
}

func (r ResourceRule) matches(group, resource string) bool {
	if r.All {
		return true
	}
	return r.Group == group && r.Resource == resource
}

// Policy describes which requests the readonly proxy should allow.
// The zero value is equivalent to PresetStrict: reads/reviews/dry-run pass,
// everything else is blocked.
type Policy struct {
	// Name is used in debug logs and 405 error reasons.
	Name string

	// AllowWriteResources lists (group, resource) pairs that may be mutated.
	AllowWriteResources []ResourceRule

	// Namespaces, if non-empty, restricts mutating operations to these
	// namespaces. Reads pass through unchanged. Mutations on cluster-scoped
	// or cross-namespace (deletecollection-style) paths are blocked when a
	// namespace allowlist is in effect; use an empty Namespaces list to
	// allow cluster-scoped writes.
	Namespaces []string

	// AllowUpgrade permits protocol upgrades on the upgrade subresources
	// (exec, attach, portforward, proxy). Mutating requests on other paths
	// are NOT bypassed by an Upgrade header — they still go through the
	// usual write/namespace checks.
	AllowUpgrade bool
}

// Decide returns ("", true) if the request is allowed, or (reason, false)
// if it should be blocked. The reason is embedded in the 405 response.
func (p Policy) Decide(r *http.Request) (reason string, allowed bool) {
	info := parseAPIPath(r.URL.Path)
	upgrade := isUpgrade(r)
	_, isUpgradeSub := upgradeSubresources[info.Subresource]

	// Upgrade header anywhere is suspect; block regardless of path/method.
	// This preserves the original readonly proxy behavior and closes smuggling
	// attacks where an Upgrade header on DELETE /pods/<n> would bypass policy.
	if upgrade {
		if isUpgradeSub {
			// More specific message for upgrade subresource paths
			return p.deny(fmt.Sprintf("protocol upgrade on %s subresource not allowed", info.Subresource)), false
		}
		return p.deny("protocol upgrade not permitted on this path"), false
	}

	// Safe methods (GET/HEAD/OPTIONS) are always allowed when there's no
	// Upgrade header, matching the original readonly proxy behavior. This
	// permits plain GETs to paths like /pods/x/proxy for debugging.
	if isReadOnly(r) {
		return "", true
	}

	// Upgrade subresources (exec/attach/portforward/proxy) require
	// AllowUpgrade for non-safe methods (POST/PUT/DELETE/etc), since they
	// tunnel traffic past HTTP filtering. Namespace allowlist still applies.
	if isUpgradeSub {
		if !p.AllowUpgrade {
			return p.deny(fmt.Sprintf("%s on %s subresource not allowed", r.Method, resourceLabel(info))), false
		}
		if reason, ok := p.checkNamespace(info); !ok {
			return reason, false
		}
		return "", true
	}
	if isNonMutatingPost(r) {
		return "", true
	}
	if isDryRun(r) {
		return "", true
	}

	// Beyond this point we are evaluating a mutating request.
	if info.Resource == "" {
		return p.deny(fmt.Sprintf("%s requests are not allowed", r.Method)), false
	}

	if reason, ok := p.checkNamespace(info); !ok {
		return reason, false
	}

	if !p.allowsWrite(info) {
		return p.deny(fmt.Sprintf("%s on %s not allowed", r.Method, resourceLabel(info))), false
	}
	return "", true
}

// checkNamespace enforces the Namespaces allowlist for mutating requests.
// Returns ok=true when the request is allowed to proceed.
func (p Policy) checkNamespace(info APIPath) (reason string, ok bool) {
	if len(p.Namespaces) == 0 {
		return "", true
	}
	target := info.Namespace
	// Mutations on `namespaces/<name>` are scoped to <name>, not a parent ns.
	if info.Namespace == "" && info.Resource == "namespaces" && info.Name != "" {
		target = info.Name
	}
	if target == "" {
		return p.deny(fmt.Sprintf("mutation on cluster-scoped or cross-namespace path %s not allowed while --namespace allowlist is set", resourceLabel(info))), false
	}
	if !contains(p.Namespaces, target) {
		return p.deny(fmt.Sprintf("namespace %q not in policy allowlist", target)), false
	}
	return "", true
}

func (p Policy) allowsWrite(info APIPath) bool {
	for _, rule := range p.AllowWriteResources {
		if rule.matches(info.Group, info.Resource) {
			return true
		}
	}
	return false
}

func (p Policy) deny(msg string) string {
	if p.Name == "" {
		return msg
	}
	return msg + " (policy " + p.Name + ")"
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
