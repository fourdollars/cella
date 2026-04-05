package proxy

// restartUserServices is the generic shell snippet used in SetupContainer.
// It restarts all active user systemd services for every non-root user that
// has a live systemd --user session (/run/user/<uid> exists).
// This is service-agnostic: we don't know (or care) what is running — any
// process that was started before NODE_EXTRA_CA_CERTS was set needs a restart
// to pick up the new environment variable.
const restartUserServicesScript = `
for uid in $(ls /run/user/ 2>/dev/null); do
  [ "$uid" -eq 0 ] 2>/dev/null && continue
  user=$(id -nu "$uid" 2>/dev/null) || continue
  export XDG_RUNTIME_DIR=/run/user/$uid
  units=$(sudo -u "$user" systemctl --user list-units --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
  [ -z "$units" ] && continue
  sudo -u "$user" systemctl --user restart $units 2>/dev/null || true
done
`
