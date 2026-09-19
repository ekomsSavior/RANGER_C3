// Package payloads provides a registry of all implant payloads.
package payloads

import (
	"encoding/json"
	"fmt"
)

// ExecuteByName runs a payload by name with the given arguments.
// Returns JSON output or an error.
func ExecuteByName(name string, args map[string]string) ([]byte, error) {
	payload, ok := Get(name)
	if !ok {
		return nil, fmt.Errorf("unknown payload: %s", name)
	}
	return payload.Execute(args)
}

// ExecuteTaskArgs converts a generic payload map to args map suitable for Execute.
func ExecuteTaskArgs(payload map[string]any) map[string]string {
	args := make(map[string]string)
	for k, v := range payload {
		switch val := v.(type) {
		case string:
			args[k] = val
		case []byte:
			args[k] = string(val)
		default:
			if b, err := json.Marshal(v); err == nil {
				args[k] = string(b)
			}
		}
	}
	return args
}
