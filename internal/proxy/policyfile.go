package proxy

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

// policyFile is the on-disk representation of a Policy.
//
// Example:
//
//	name: my-policy            # optional; default is the file's basename
//	allowUpgrade: true
//	namespaces: [dev, staging]
//	allowWriteResources:
//	  - configmaps
//	  - apps/deployments
//	  - "*"                   # allow all (use sparingly)
//
// `name` appears in 405 error messages returned to kubectl, so prefer a
// short label without secrets or filesystem paths.
type policyFile struct {
	Name                string   `json:"name,omitempty"`
	AllowUpgrade        bool     `json:"allowUpgrade,omitempty"`
	Namespaces          []string `json:"namespaces,omitempty"`
	AllowWriteResources []string `json:"allowWriteResources,omitempty"`
}

// LoadPolicyFile reads a YAML policy file from disk and validates it. Unknown
// top-level fields cause an error so typos like `allowWriteResource` don't
// silently produce a deny-all policy.
func LoadPolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy file: %w", err)
	}
	var pf policyFile
	if err := yaml.UnmarshalStrict(data, &pf); err != nil {
		return Policy{}, fmt.Errorf("parse policy file %s: %w", path, err)
	}

	rules, err := ParseResourceRules(pf.AllowWriteResources)
	if err != nil {
		return Policy{}, fmt.Errorf("policy file %s: %w", path, err)
	}

	name := pf.Name
	if name == "" {
		name = filepath.Base(path)
	}
	return Policy{
		Name:                name,
		AllowUpgrade:        pf.AllowUpgrade,
		Namespaces:          pf.Namespaces,
		AllowWriteResources: rules,
	}, nil
}

// ParseResourceRules parses a slice of string tokens into ResourceRules,
// surfacing parse errors at config-load time.
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
