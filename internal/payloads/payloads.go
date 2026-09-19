// Package payloads provides a registry of all implant payloads.
// Each payload implements the Payload interface and self-registers in an init().
package payloads

import (
	"encoding/json"
	"sort"
)

// Payload is the interface all payload modules implement.
type Payload interface {
	// Name returns the unique payload name (matches manifest).
	Name() string
	// Category returns the payload category (recon, credential, collection, etc.).
	Category() string
	// Description returns a brief description of what the payload does.
	Description() string
	// Execute runs the payload with the given arguments and returns JSON output.
	Execute(args map[string]string) ([]byte, error)
}

// Registry holds all registered payloads by name.
var registry = make(map[string]Payload)

// Register adds a payload to the global registry. Called from init().
func Register(p Payload) {
	registry[p.Name()] = p
}

// Get returns a payload by name.
func Get(name string) (Payload, bool) {
	p, ok := registry[name]
	return p, ok
}

// List returns all registered payloads sorted by name.
func List() []Payload {
	out := make([]Payload, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name() < out[j].Name()
	})
	return out
}

// PayloadInfo is a summary of a payload for listing.
type PayloadInfo struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// Info returns a summary of all registered payloads.
func Info() []PayloadInfo {
	list := List()
	out := make([]PayloadInfo, len(list))
	for i, p := range list {
		out[i] = PayloadInfo{
			Name:        p.Name(),
			Category:    p.Category(),
			Description: p.Description(),
		}
	}
	return out
}

// MarshalJSON is a helper to produce JSON from any value.
func MarshalJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
