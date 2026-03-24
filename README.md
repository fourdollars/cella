# cella

> Latin: *cella* — a small room. The original container.

A terminal UI and CLI for managing and monitoring LXD + Docker containers with real-time metrics, syscall tracing, DNS traffic monitoring, and security policy enforcement.

![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

### 📊 Real-time Monitoring
- **CPU** — per-container usage via cgroup v2, with sparkline history graphs
- **Memory** — current/limit with progress bars showing host utilization
- **Network** — RX/TX rates with sparkline trends (↓ blue / ↑ green)
- **Disk I/O** — read/write rates via cgroup `io.stat` (LXD) or `blkio_stats` (Docker)
- **Per-CPU** — individual CPU core usage bars for pinned containers (`limits.cpu`)
- **Host resources** — total CPU threads, memory, load average as reference baseline

### 🔬 Syscall Tracing
- Live per-container syscall activity via **bpftrace** (eBPF)
- Top syscalls table with family grouping (file, network, process, memory, etc.)
- Seccomp profile generator — creates strict/moderate/permissive JSON profiles from observed syscalls
- Sidebar trace indicator (🔬) for actively traced containers

### 🛡️ Security Policy Engine
- **Seccomp profiles** — apply strict/moderate/permissive profiles with one keypress
- **AppArmor** — display current profile status
- **Egress control** — per-container nftables rules on the FORWARD chain
- **DNS Monitor** — live DNS traffic observatory with allow/deny controls
- **Security flags** — display privileged mode and nesting status

### 🔍 DNS Monitor (NEW)
- Captures live DNS queries from containers via `tcpdump` on the bridge interface
- Displays domain names, resolved IPs, query counts, and timestamps
- Interactive allow/deny — mark domains and automatically generate nftables rules
- Per-container view with egress restriction status indicator

### 🐳 Multi-Runtime
- **LXD** containers via unix socket API
- **Docker** containers via Docker Engine API
- Unified sidebar with runtime indicators (🔷 LXD / 🐳 Docker)
- Runtime filter cycling (`f` key) — show All / LXD only / Docker only
- Parallel fetch for responsive UI with many containers

### 📋 Container Management
- Start / Stop / Pause / Unpause
- Exec commands inside containers (with interactive shell support)
- Log streaming (follow mode with `journalctl` or `docker logs`)
- Snapshot & Clone
- Resource limits editing (CPU, memory)
- Config export (JSON) / import
- Container create & destroy

---

## Quick Start

```bash
# Build
make build

# Run the TUI
./cella

# List all containers (LXD + Docker)
./cella list

# List with runtime filter
./cella list --runtime lxd
./cella list --runtime docker

# Execute a command in a container
./cella exec <container-name> -- <command>
```

---

## Keyboard Shortcuts

### Navigation
| Key | Action |
|-----|--------|
| `↑` `k` / `↓` `j` | Navigate container list |
| `g` | Go to container by number |
| `1` `2` `3` | Sort by name / CPU% / memory |
| `f` | Cycle runtime filter (All → LXD → Docker) |
| `?` | Toggle help overlay |
| `q` | Quit (with confirmation) |
| `Ctrl+C` | Quit (with confirmation) |

### Container Actions
| Key | Action |
|-----|--------|
| `s` | Start / `x` Stop / `p` Pause |
| `e` | Exec command inside container |
| `l` | Stream logs (follow mode) |
| `+` | Create new container |
| `d` | Destroy container (with confirmation) |

### Panels
| Key | Panel |
|-----|-------|
| `r` | Resources (CPU/memory limits, host stats) |
| `n` | Snapshots & clone |
| `t` | Syscall tracing (start bpftrace) |
| `T` | Stop tracing |
| `G` | Generate seccomp profile from trace |
| `w` | Network connections |
| `P` | Security policy (seccomp / egress) |
| `H` | DNS monitor (traffic / allow / deny) |
| `E` | Export container config (JSON) |
| `I` | Import container config |

### DNS Monitor (`H` panel)
| Key | Action |
|-----|--------|
| `↑` `↓` | Select domain |
| `a` | Allow domain (add nftables accept rule) |
| `x` | Deny domain (enable egress restriction) |
| `u` | Unset allow/deny marking |

### Policy Panel (`P`)
| Key | Action |
|-----|--------|
| `1` `2` `3` | Apply seccomp profile (strict/moderate/permissive) |
| `a` | Add egress allow rule (resolves domain → IPv4) |
| `d` | Delete all egress rules (with confirmation) |
| `r` | Refresh policy info |

---

## Architecture

```
cella
├── cmd/                    # CLI entry point (cobra)
│   └── main.go
├── internal/
│   ├── tui/                # Terminal UI (Bubbletea + Lipgloss)
│   │   └── app.go          # Main TUI application (~4000 lines)
│   ├── lxd/                # LXD client (unix socket REST API)
│   │   └── client.go
│   ├── runtime/             # Multi-runtime abstraction
│   │   ├── types.go         # Runtime interface
│   │   ├── lxd_adapter.go   # LXD runtime adapter
│   │   └── docker.go        # Docker runtime adapter
│   ├── metrics/             # Metrics collection
│   │   ├── cgroup.go        # cgroup v2 CPU/memory/IO
│   │   └── ring.go          # Ring buffer for sparklines
│   ├── security/            # Security & network control
│   │   ├── egress.go        # nftables egress rules (FORWARD chain)
│   │   ├── dns_monitor.go   # DNS traffic capture & analysis
│   │   ├── seccomp.go       # Seccomp profile management
│   │   └── profiles.go      # Built-in seccomp profiles
│   └── trace/               # Syscall tracing
│       └── tracer.go        # bpftrace integration
├── Makefile
├── go.mod
└── go.sum
```

### Key Design Decisions

- **`ip` family nftables** — egress rules use `ip` family FORWARD chain (not `inet`), matching bridge traffic via `iifname "lxdbr0"` + container source IP. Priority -5 ensures rules evaluate before Docker's filter chain.
- **Docker + LXD coexistence** — Docker sets iptables FORWARD policy to DROP; cella's rules in `ip cella` table run at a higher priority to avoid conflicts.
- **`sudo -n`** — all privileged operations (nft, bpftrace, tcpdump) use `sudo -n` (non-interactive) to prevent TUI from blocking on password prompts.
- **Parallel runtime fetch** — container data from LXD and Docker is fetched concurrently, merged into a unified view.
- **DNS ↔ nftables integration** — DNS monitor captures domain→IP mappings; allow/deny actions translate to concrete nftables rules using resolved IPv4 addresses.

---

## Requirements

- **Linux** with LXD and/or Docker installed
- **Go 1.24+** (build only)
- **bpftrace** (optional, for syscall tracing)
- **tcpdump** (optional, for DNS monitoring)
- **nftables** (optional, for egress control)
- **sudo** with `NOPASSWD` for the running user (for nft, bpftrace, tcpdump)
- Single binary deployment — no runtime dependencies beyond the Go standard library

### Tested On
- Ubuntu 24.04 LTS (Noble) with kernel 6.17
- LXD 5.x (snap) + Docker 27.x
- Go 1.26.1

---

## CLI

```
Usage:
  cella [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  exec        Execute a command in a container
  help        Help about any command
  list        List containers from all runtimes

Flags:
  -h, --help   help for cella

Use "cella [command] --help" for more information about a command.
```

### `cella list`

```
$ cella list
  #  RT     NAME                   STATE    IP               CPU%    MEM
───────────────────────────────────────────────────────────────────────────
  0  🔷lxd  juju-1923fb-2          RUNNING  10.25.54.145     0.3%   162MB
  1  🔷lxd  juju-634dd5-0          RUNNING  10.25.54.220     1.1%   591MB
  2  🔷lxd  juju-76edad-0          RUNNING  10.25.54.235     0.5%   705MB
  3  🔷lxd  juju-fa5703-0          RUNNING  10.25.54.133     0.8%   219MB

  Summary: 4 running (lxd: 4)
```

Flags:
- `-r`, `--runtime` — filter by runtime (`lxd` or `docker`)
- `-s`, `--sort` — sort by `name`, `cpu`, or `mem`
- `-w`, `--watch` — continuous monitoring mode (refreshes every 2s)

---

## Design Inspiration

- **[NemoClaw](https://github.com/openclaw/openclaw)** — per-agent container isolation, policy engine, egress control concepts
- **[kbox Web Observatory](https://github.com/sysprog21/kbox)** — real-time syscall activity monitoring, kernel metrics, event streaming

---

## Stats

- **52 commits** on main
- **~7,800 lines** of Go
- **6 internal packages**: tui, lxd, runtime, metrics, security, trace
- **5 metric collectors**: CPU, Memory, Network, Disk I/O, Syscall
- **2 runtime backends**: LXD, Docker
- **12 TUI panels**: Dashboard, Exec, Logs, Syscall, Seccomp Gen, Resources, Snapshots, Network, Policy, DNS Monitor, Create, Help

---

## License

MIT
