// Command payloads builds each Go payload as a standalone CLI binary.
//
// Build individual payloads:
//
//	go run ./cmd/payloads --list              # List all payloads
//	go run ./cmd/payloads sysrecon            # Run sysrecon
//	go run ./cmd/payloads --name sysrecon --arg quick=true
//
// Cross-compile a payload:
//
//	GOOS=linux GOARCH=amd64 go build -o sysrecon_linux ./cmd/payloads && ./sysrecon_linux sysrecon
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/saviorSEC/ranger/internal/payloads"
)

func main() {
	// All payloads auto-register on import
	_ = payloads.Info()

	args := os.Args[1:]

	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Ranger C3 - Go Payloads")
		fmt.Println()
		fmt.Println("Usage: payloads <payload_name> [--arg key=value ...]")
		fmt.Println("       payloads --list")
		fmt.Println("       payloads --help")
		fmt.Println()
		fmt.Println("Available payloads:")
		for _, p := range payloads.List() {
			fmt.Printf("  %-20s [%-12s] %s\n", p.Name(), p.Category(), p.Description())
		}
		return
	}

	if args[0] == "--list" {
		info := payloads.Info()
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))
		return
	}

	payloadName := args[0]

	// Parse --arg key=value pairs
	execArgs := make(map[string]string)
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "--arg=") {
			kv := strings.TrimPrefix(a, "--arg=")
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				execArgs[parts[0]] = parts[1]
			}
		} else if strings.HasPrefix(a, "--") {
			kv := strings.TrimPrefix(a, "--")
			if strings.Contains(kv, "=") {
				parts := strings.SplitN(kv, "=", 2)
				execArgs[parts[0]] = parts[1]
			}
		} else if strings.Contains(a, "=") {
			parts := strings.SplitN(a, "=", 2)
			execArgs[parts[0]] = parts[1]
		}
	}

	result, err := payloads.ExecuteByName(payloadName, execArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}
