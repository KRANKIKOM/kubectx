package proxy

import "strings"

// APIPath holds the parsed components of a Kubernetes API URL.
//
// Examples:
//
//	/api/v1/pods                                  -> {Resource: "pods"}
//	/api/v1/namespaces/foo                        -> {Resource: "namespaces", Name: "foo"}  (request for one namespace; cluster-scoped)
//	/api/v1/namespaces/foo/pods                   -> {Namespace: "foo", Resource: "pods"}
//	/api/v1/namespaces/foo/pods/bar               -> {Namespace: "foo", Resource: "pods", Name: "bar"}
//	/api/v1/namespaces/foo/pods/bar/log           -> {Namespace: "foo", Resource: "pods", Name: "bar", Subresource: "log"}
//	/apis/apps/v1/namespaces/foo/deployments      -> {Group: "apps", Namespace: "foo", Resource: "deployments"}
//	/apis/apps/v1/deployments                     -> {Group: "apps", Resource: "deployments"}  (cross-namespace list/deleteCollection)
//	/api/v1/nodes/n1                              -> {Resource: "nodes", Name: "n1"}          (cluster-scoped)
//	/healthz                                      -> zero APIPath (unrecognized — callers treat as deny)
type APIPath struct {
	Group       string
	Version     string
	Namespace   string
	Resource    string
	Name        string
	Subresource string
}

// parseAPIPath parses a Kubernetes API request path.
// Returns a zero APIPath if the path doesn't match the expected shape.
func parseAPIPath(path string) APIPath {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return APIPath{}
	}

	var p APIPath
	var rest []string

	switch parts[0] {
	case "api":
		if len(parts) < 2 {
			return APIPath{}
		}
		p.Version = parts[1]
		rest = parts[2:]
	case "apis":
		if len(parts) < 3 {
			return APIPath{}
		}
		p.Group = parts[1]
		p.Version = parts[2]
		rest = parts[3:]
	default:
		return APIPath{}
	}

	// Drop a trailing empty segment (e.g. "/api/v1/pods/").
	if len(rest) > 0 && rest[len(rest)-1] == "" {
		rest = rest[:len(rest)-1]
	}

	if len(rest) >= 2 && rest[0] == "namespaces" {
		// `/namespaces/<name>` alone is a request targeting that namespace
		// as a resource (cluster-scoped). `/namespaces/<name>/{status,finalize}`
		// are namespace subresources, not namespaced sub-paths. Anything
		// else (`/namespaces/<name>/pods/...`) is namespace-scoped.
		if len(rest) == 2 {
			p.Resource = "namespaces"
			p.Name = rest[1]
			return p
		}
		if len(rest) == 3 && isNamespaceSubresource(rest[2]) {
			p.Resource = "namespaces"
			p.Name = rest[1]
			p.Subresource = rest[2]
			return p
		}
		p.Namespace = rest[1]
		rest = rest[2:]
	}

	if len(rest) >= 1 {
		p.Resource = rest[0]
	}
	if len(rest) >= 2 {
		p.Name = rest[1]
	}
	if len(rest) >= 3 {
		p.Subresource = rest[2]
	}
	return p
}

// isNamespaceSubresource reports whether s is a known subresource of
// the core `namespaces` resource.
func isNamespaceSubresource(s string) bool {
	return s == "status" || s == "finalize"
}
