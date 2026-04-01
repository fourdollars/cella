# cella

> **⚠️ Work In Progress** — actively developed, interfaces may change

> Latin: *cella* — a small room. The original container.

A terminal UI and CLI for managing and monitoring LXD + Docker containers — real-time metrics, syscall tracing, HTTPS interception with operator approval, and AI inference monitoring.

![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-WIP-orange)
[![GitHub Pages](https://img.shields.io/badge/Docs-GitHub%20Pages-blue)](https://fourdollars.github.io/cella/)

---

## ⚠️ Work In Progress

cella is under active development. Core features work well, but:
- APIs and key bindings may change between versions
- Some features require root / `sudo` (bpftrace, nftables)
- The HTTPS interception and inference routing features are experimental

Feedback, bug reports, and contributions welcome.

---

## Features

### 📊 Real-time Monitoring
- **CPU** — per-container usage via cgroup v2, with sparkline history
- **Memory** — current/limit with color-coded progress bars
- **Network** — RX/TX rates with sparklines
- **Disk I/O** — read/write rates via cgroup `io.stat` / `blkio_stats`
- **Per-CPU** — individual CPU core bars for pinned containers
- **Host resources** — total CPU, memory, load average as reference

### 🔬 Syscall Monitoring — Dual Mode
- **Passive monitoring** (always-on): bpftrace samples all syscall activity every 5s
  - Family breakdown: file, network, process, memory, signal, ipc
  - Top-12 syscall table with activity sparkline
  - **Seccomp profile generator** — observe syscalls, generate OCI seccomp JSON (`G` key)
- **Active blocking** (per-container, opt-in): `Z` key in Policy panel
  - Applies `security.syscalls.deny` BPF filter via LXD API
  - Blocks dangerous syscalls (`ptrace`, `mount`, `bpf`, `kexec_load`, etc.) with EPERM
  - Operator approval overlay: bpftrace detects attempts → `[y]` unblock once / `[Y]` permanent / `[n]` keep blocked

### 🔐 HTTPS Interception + Operator Approval *(WIP)*
- Transparent MITM proxy via **nftables REDIRECT** — no proxy env vars needed
- Works with Node.js (via `NODE_EXTRA_CA_CERTS`), Python, curl, and more
- **One key setup** (`A` → `p`): auto-generates CA cert, sets up nftables REDIRECT, injects CA into container
- Operator approval TUI: each new domain triggers `[y] allow once / [Y] always / [n] deny`
- **HTTP/2 aware** — intercepts modern APIs including GitHub Copilot
- Audit log with filtering, text search, and JSON export

### 📊 AI Inference Monitoring *(WIP)*
- Tracks API calls to OpenAI, Anthropic, GitHub Copilot, Gemini, and more
- Per-model stats: requests, tokens in/out, RPM, RPH, TPM
- **Cost estimation** for 27+ models with per-minute sparklines
- Session breakdown by container
- `M` key for inference stats panel, `S` to export JSON

### 🔀 Inference Routing *(WIP)*
- Redirect AI API calls to alternative backends transparently
- Presets: OpenAI/Anthropic/Copilot/Gemini → local Ollama or NVIDIA Endpoint
- Custom route wizard, enable/disable per-domain, save to file

### 🛡️ Security Policy Engine
- **Seccomp profiles** — apply strict/moderate/permissive with one keypress
- **AppArmor** — display and manage profiles
- **Egress control** — nftables per-container allow/block rules
- **DNS monitor** — live DNS traffic with allow/deny list
- YAML policy export/import

### 📦 Container Lifecycle
- LXD + Docker unified management
- start / stop / pause / exec / logs / snapshot / clone / create / delete
- Resource limits editing (CPU, memory) via LXD API
- Config export/import (JSON)

---

## Installation

### Pre-built binary (Linux amd64/arm64)

```bash
# Auto-detect architecture
ARCH=$(uname -m); [ "$ARCH" = "aarch64" ] && ARCH=arm64 || ARCH=amd64
curl -Lo cella https://github.com/fourdollars/cella/releases/download/latest/cella_linux_${ARCH}
chmod +x cella
sudo ./cella
```

Or download manually for your architecture:
- **amd64** (x86_64): `curl -Lo cella https://github.com/fourdollars/cella/releases/download/latest/cella_linux_amd64`
- **arm64** (aarch64/Raspberry Pi 4+): `curl -Lo cella https://github.com/fourdollars/cella/releases/download/latest/cella_linux_arm64`

### Build from source

```bash
git clone https://github.com/fourdollars/cella
cd cella
go build -o cella ./cmd/
```

Requires Go 1.20+, Linux kernel 5.8+ (for bpftrace / eBPF features).

---

## Quick Start

```bash
# Run the TUI
sudo ./cella

# List all containers (LXD + Docker)
./cella list
./cella list --watch --sort cpu

# Execute a command in a container
./cella exec mycontainer -- bash
```

---

## Key Bindings

| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Navigate containers |
| `1/2/3` | Sort by name / CPU / memory |
| `f` | Cycle runtime filter (All → LXD → Docker) |
| `/` | Search by name |
| `s/x/p` | Start / Stop / Pause container (`s` also unfreezes Frozen containers) |
| `e` | Exec command / shell |
| `l` | Logs (streaming) |
| `+` / `d` | Create / Delete container |
| `w` | Network panel |
| `r` | Resource limits panel |
| `n` | Snapshots & clone (shows size for zfs/btrfs/lvm storage) |
| `t` / `T` | Start / stop syscall trace |
| `G` / `S` | Generate / save seccomp profile |
| `Z` | Toggle syscall blocking from **any panel** (applies `security.syscalls.deny`) |
| `P` | Security policy panel |
| `D` | DNS monitor panel |
| `A` | **API audit panel** (HTTPS interception) |
| `M` | **Inference stats panel** |
| `R` | **Inference routing panel** |
| `V` | Events log |
| `E` / `I` | Export / Import config |
| `?` | Help overlay |
| `q` | Quit |

---

## Requirements

- Linux (Ubuntu 22.04+ recommended)
- LXD and/or Docker daemon running
- `lxd` group membership (or run with `sudo`) for LXD management
- `bpftrace` + `sudo` for syscall tracing
- `nftables` + `sudo` for egress control and HTTPS interception

---

## Architecture

cella is written in Go using [Bubbletea](https://github.com/charmbracelet/bubbletea) for the TUI. It communicates with LXD via its Unix socket REST API, and with Docker via the Docker socket.

```
cella (~15MB binary, 14,514 lines of Go, 52 files)
├── cmd/            CLI entry point (cobra) + subcommands
├── internal/
│   ├── proxy/      HTTP interception, MITM, audit, inference routing
│   ├── tui/        Bubbletea TUI (20 panels)
│   ├── security/   Seccomp, AppArmor, egress, DNS monitor
│   ├── trace/      bpftrace-based syscall tracing + seccomp generator
│   ├── runtime/    LXD + Docker runtime abstraction
│   ├── lxd/        LXD REST API client + seccomp syscall blocking
│   └── metrics/    cgroup v2 metrics
└── docs/           GitHub Pages site
```

---

## Status

| Feature | Status |
|---------|--------|
| Container management | ✅ Stable |
| Real-time metrics | ✅ Stable |
| Syscall tracing (bpftrace) | ✅ Stable |
| Syscall blocking (LXD BPF deny) | ✅ Stable |
| Security policy | ✅ Stable |
| HTTPS interception | 🚧 WIP |
| Inference stats | 🚧 WIP |
| Inference routing | 🚧 WIP |
| Inference request body capture | 📋 Planned |
| Multi-host support | 📋 Planned |

---

## License

MIT — see [LICENSE](LICENSE)

Built by [Shih-Yuan Lee (@fourdollars)](https://github.com/fourdollars)
