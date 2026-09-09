// Ranger C3 - Distributed C2 Server with P2P Mesh
//
// Usage:
//
//	go run ./cmd/c2 --listen :4443 --db data/c2.db --password "changeme" --key <session-key-hex>
//	go run ./cmd/c2 --listen :4443 --mesh :9000 --bootstrap "10.0.0.2:9000"
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/saviorSEC/ranger/internal/api"
	"github.com/saviorSEC/ranger/internal/mesh"
	"github.com/saviorSEC/ranger/internal/protocol"
	"github.com/saviorSEC/ranger/internal/store"
)

func main() {
	listen := flag.String("listen", ":4443", "C2 listen address")
	meshListen := flag.String("mesh", "", "Mesh P2P listen address (empty = no mesh)")
	bootstrap := flag.String("bootstrap", "", "Comma-separated bootstrap mesh peers")
	dbPath := flag.String("db", "data/c2.db", "Database path")
	password := flag.String("password", "", "Operator dashboard password (plaintext or bcrypt hash)")
	keyHex := flag.String("key", "", "Session key hex (32 bytes). Omit to generate and print one")
	tlsCert := flag.String("cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	generateCerts := flag.Bool("gen-certs", false, "Generate self-signed TLS certs")
	c2ID := flag.String("id", "", "C2 node ID (auto if empty)")
	flag.Parse()

	// Generate or use C2 ID
	nodeID := *c2ID
	if nodeID == "" {
		b := make([]byte, 16)
		rand.Read(b)
		nodeID = fmt.Sprintf("c2-%x", b)[:20]
	}

	// Ensure data directory
	os.MkdirAll(filepath.Dir(*dbPath), 0700)

	// Generate self-signed certs if requested
	if *generateCerts {
		certFile, keyFile, err := generateSelfSignedCert(nodeID)
		if err != nil {
			log.Fatalf("cert generation: %v", err)
		}
		tlsCert = &certFile
		tlsKey = &keyFile
		log.Printf("[c2] generated self-signed cert: %s / %s", certFile, keyFile)
	}

	// Open database
	st, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer st.Close()

	// Session key for implant comms. When not provided, generate one and
	// print it so implants can be provisioned with the same key.
	var sessionKey []byte
	if *keyHex != "" {
		var err error
		sessionKey, err = hex.DecodeString(*keyHex)
		if err != nil {
			log.Fatalf("bad -key hex: %v", err)
		}
		if len(sessionKey) != 32 {
			log.Fatalf("-key must decode to 32 bytes, got %d", len(sessionKey))
		}
	} else {
		sessionKey = make([]byte, 32)
		if _, err := rand.Read(sessionKey); err != nil {
			log.Fatalf("keygen: %v", err)
		}
		log.Printf("[c2] generated session key (provision implants with -key): %x", sessionKey)
	}

	// Build API server config
	apiCfg := api.Config{
		ListenAddr:  *listen,
		C2ID:        nodeID,
		SessionKey:  sessionKey,
		TLSEnabled:  *tlsCert != "" && *tlsKey != "",
		TLSCertFile: *tlsCert,
		TLSKeyFile:  *tlsKey,
		Store:       st,
		DashboardPW: *password,
	}

	srv, err := api.New(apiCfg)
	if err != nil {
		log.Fatalf("api: %v", err)
	}

	// Start mesh networking if configured
	if *meshListen != "" {
		meshCert, err := generateMeshCert(nodeID)
		if err != nil {
			log.Fatalf("mesh cert: %v", err)
		}

		var bootstrapPeers []string
		if *bootstrap != "" {
			bootstrapPeers = strings.Split(*bootstrap, ",")
		}

		meshCfg := mesh.Config{
			NodeID:     nodeID,
			ListenAddr: *meshListen,
			Bootstrap:  bootstrapPeers,
			TLSCert:    *meshCert,
			OnHeartbeat: func(hb *protocol.MeshHeartbeat) {
				log.Printf("[mesh] heartbeat from %s", hb.NodeID[:8])
			},
			OnPeerJoin: func(n *protocol.MeshNode) {
				log.Printf("[mesh] peer joined: %s @ %s", n.ID[:8], n.Addr)
				st.UpsertMeshNode(n)
			},
			OnPeerLeave: func(id string) {
				log.Printf("[mesh] peer left: %s", id[:8])
			},
		}

		meshNode := mesh.NewNode(meshCfg)
		if err := meshNode.Start(); err != nil {
			log.Fatalf("mesh: %v", err)
		}
		defer meshNode.Stop()

		log.Printf("[c2] mesh node active on %s", *meshListen)
	}

	// Print banner
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Println("  RANGER C3 - Distributed Mesh C2 Framework")
	fmt.Println("  Node:", nodeID[:12]+"...")
	fmt.Println("  Listen:", *listen)
	fmt.Println("  TLS:", *tlsCert != "")
	fmt.Println("  Mesh:", *meshListen)
	fmt.Println("  DB:", *dbPath)
	fmt.Println("  SessionKey:", hex.EncodeToString(sessionKey[:8])+"...")
	fmt.Println("=" + strings.Repeat("=", 59))

	// Start the server
	if err := srv.Start(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func generateSelfSignedCert(nodeID string) (certFile, keyFile string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"Ranger C3"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return "", "", err
	}

	certDir := "certs"
	os.MkdirAll(certDir, 0700)

	certFile = filepath.Join(certDir, "c2-cert.pem")
	keyFile = filepath.Join(certDir, "c2-key.pem")

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certFile, keyFile, nil
}

func generateMeshCert(nodeID string) (*tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"Ranger Mesh"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        template,
	}

	return tlsCert, nil
}

// Ensure net, uuid are used
var _ = net.IPv4len
