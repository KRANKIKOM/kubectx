package proxy

import "fmt"

// PresetStrict matches the original `-r` behavior: reads only, no exec, no writes.
func PresetStrict() Policy {
	return Policy{Name: "strict"}
}

// PresetRelaxed allows shell access (exec/attach/portforward/proxy via
// AllowUpgrade) plus writes to the resources most commonly tweaked during
// debugging: ConfigMaps/Secrets for config edits, Deployments/StatefulSets
// for `kubectl rollout restart`.
func PresetRelaxed() Policy {
	return Policy{
		Name:         "relaxed",
		AllowUpgrade: true,
		AllowWriteResources: []ResourceRule{
			{Resource: "configmaps"},
			{Resource: "secrets"},
			{Group: "apps", Resource: "deployments"},
			{Group: "apps", Resource: "statefulsets"},
		},
	}
}

// PresetDebug allows everything — equivalent to running without `-r`.
// Useful as a starting point for custom policies.
func PresetDebug() Policy {
	return Policy{
		Name:                "debug",
		AllowUpgrade:        true,
		AllowWriteResources: []ResourceRule{{All: true}},
	}
}

// PresetByName returns a preset by name, or an error if unknown.
func PresetByName(name string) (Policy, error) {
	switch name {
	case "", "strict":
		return PresetStrict(), nil
	case "relaxed":
		return PresetRelaxed(), nil
	case "debug":
		return PresetDebug(), nil
	}
	return Policy{}, fmt.Errorf("unknown preset %q (valid: strict, relaxed, debug)", name)
}
