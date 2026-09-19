//go:build linux && !amd64

package payloads

import "errors"

// ProcessInject is a stub on architectures where the amd64 ptrace-based
// injector is unavailable (for example linux/arm64 or linux/386).
type ProcessInject struct{}

func init() {
	Register(&ProcessInject{})
}

func (p *ProcessInject) Name() string     { return "process_inject" }
func (p *ProcessInject) Category() string { return "persistence" }
func (p *ProcessInject) Description() string {
	return "Linux process injection via ptrace (linux/amd64 only)"
}

func (p *ProcessInject) Execute(args map[string]string) ([]byte, error) {
	return nil, errors.New("process_inject is only supported on linux/amd64")
}
