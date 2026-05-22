package proxy

import "fmt"

// PresetStrict matches the original `-r` behavior: reads only, no exec, no writes.
func PresetStrict() *Policy {
	return &Policy{Name: "strict"}
}

// PresetRelaxed allows shell access and writes to commonly-debugged resources.
// Aimed at "I need to tweak a configmap and exec into a pod" workflows.
func PresetRelaxed() *Policy {
	return &Policy{
		Name:         "relaxed",
		AllowUpgrade: true,
		AllowWriteResources: []string{
			"configmaps",
			"secrets",
			"apps/deployments",
			"apps/statefulsets",
		},
	}
}

// PresetDebug allows everything — equivalent to running without `-r`.
// Useful as a starting point for custom policies.
func PresetDebug() *Policy {
	return &Policy{
		Name:                "debug",
		AllowUpgrade:        true,
		AllowWriteResources: []string{"*"},
	}
}

// PresetByName returns a preset by name, or an error if unknown.
func PresetByName(name string) (*Policy, error) {
	switch name {
	case "", "strict":
		return PresetStrict(), nil
	case "relaxed":
		return PresetRelaxed(), nil
	case "debug":
		return PresetDebug(), nil
	}
	return nil, fmt.Errorf("unknown preset %q (valid: strict, relaxed, debug)", name)
}
