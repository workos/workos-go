package auditlog

import (
	"strings"
)

// Action is the type to represent an Audit Log action name.
type Action string

// Category returns the action category without the environment or action name.
func (a Action) Category() string {
	index := 0
	if a.Environment() != "" {
		index = 1
	}
	parts := strings.Split(string(a), ".")

	if len(parts) <= index {
		return ""
	}

	return parts[index]
}

// Name returns the action name without the environment or category.
func (a Action) Name() string {
	index := 1
	if a.Environment() != "" {
		index = 2
	}
	parts := strings.Split(string(a), ".")

	if len(parts) <= index {
		return ""
	}

	return parts[index]
}

// Environment returns the target environment the Audit Log event will reside in
// WorkOS.
func (a Action) Environment() string {
	parts := strings.Split(string(a), ".")
	switch parts[0] {
	case "dev", "test", "internal":
		return parts[0]
	default:
		return ""
	}
}
