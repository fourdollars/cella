# cella Policy Examples

Pre-built security policy templates for common container use cases.
Import any of these into cella with `P` → `i` → type the filename.

## Profiles

| File | Seccomp | AppArmor | Egress | Use Case |
|------|---------|----------|--------|----------|
| `web-server.yaml` | strict | hardened | restricted | Public-facing web services |
| `ci-worker.yaml` | moderate | net-restricted | open | CI/CD build containers |
| `agent-sandbox.yaml` | strict | hardened | whitelist | AI agent sandboxes |
| `dev-container.yaml` | permissive | default | open | Developer workstations |
| `database.yaml` | moderate | read-only | open | Database servers |
| `custom-policy.yaml` | custom | custom | restricted | Custom rules example |

## Usage

```bash
# Apply a policy to a container
# In cella TUI: select container → P → i → examples/agent-sandbox.yaml

# Or export current container policy
# In cella TUI: select container → P → e
# Creates <container-name>-policy.yaml in current directory

# Apply from CLI (planned):
# cella policy apply --file examples/ci-worker.yaml <container-name>
```

## Security Levels

### Seccomp Profiles
- **strict** — Block dangerous syscalls (mount, ptrace, bpf), notify on file/net ops
- **moderate** — Block dangerous syscalls, allow everything else
- **permissive** — Log only, no blocking
- **custom** — Define your own syscall rules

### AppArmor Profiles
- **default** — LXD default (no custom restrictions)
- **hardened** — Deny mount, ptrace, raw/packet network, /proc/sys/kernel writes
- **net-restricted** — Deny raw/packet network only
- **read-only** — Deny all filesystem writes (except /tmp)
- **custom** — Define your own AppArmor rules

### Egress Control
- **open** — No network restrictions
- **restricted + whitelist** — Only allowed IPs/CIDRs can be reached
- Use the DNS Monitor (`D` panel) to discover domains and build your whitelist
