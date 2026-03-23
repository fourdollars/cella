# cella

> Latin: *cella* — a small room. The original container.

A terminal UI for managing and monitoring LXC/LXD containers with real-time metrics, syscall tracing, and security policy management.

## Features

- 📊 **Real-time Monitoring** — CPU, memory, network, disk via cgroup v2
- 🔬 **Syscall Tracing** — per-container syscall activity via seccomp notify / eBPF
- 🛡️ **Policy Engine** — seccomp profiles, AppArmor, egress control (nftables)
- 📋 **Container Management** — start, stop, pause, exec, logs, snapshot
- 🎯 **LXD Native** — built on the LXD Go client library

## Quick Start

```bash
# Build
make build

# Run TUI
./cella

# List containers (non-interactive)
./cella list

# Real-time monitoring
./cella top
```

## Architecture

```
cella binary
  ├── TUI (Bubbletea + Lipgloss)
  ├── LXD Client (unix socket / HTTPS)
  ├── Metrics Collector (cgroup v2)
  ├── Syscall Tracer (seccomp notify)
  └── Security Policy (seccomp / AppArmor / nftables)
```

## Design Inspiration

- **NemoClaw** — per-agent pod isolation, policy engine, egress control
- **kbox Web Observatory** — real-time syscall activity, kernel metrics, event streaming

## Requirements

- Linux with LXD/Incus installed
- Go 1.23+ (build only)
- Single binary deployment — no runtime dependencies

## License

MIT
