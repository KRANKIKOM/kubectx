package proxy

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// policyFile is the on-disk representation of a Policy.
//
// Example:
//
//	name: my-policy
//	allowUpgrade: true
//	namespaces: [dev, staging]
//	allowWriteResources:
//	  - configmaps
//	  - apps/deployments
type policyFile struct {
	Name                string   `json:"name,omitempty"`
	AllowUpgrade        bool     `json:"allowUpgrade,omitempty"`
	Namespaces          []string `json:"namespaces,omitempty"`
	AllowWriteResources []string `json:"allowWriteResources,omitempty"`
}

// LoadPolicyFile reads a YAML policy file from disk.
func LoadPolicyFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy file %s: %w", path, err)
	}
	name := pf.Name
	if name == "" {
		name = "file:" + path
	}
	return &Policy{
		Name:                name,
		AllowUpgrade:        pf.AllowUpgrade,
		Namespaces:          pf.Namespaces,
		AllowWriteResources: pf.AllowWriteResources,
	}, nil
}
