#!/bin/sh
# Install socktrail as a systemd-managed collector: the binary to /usr/local/bin
# and the unit to /etc/systemd/system, then enable and start the service.
#
# The unit streams MessagePack over a Unix socket so local subscribers can read
# it without spawning socktrail themselves. See packaging/socktrail.service for
# the capture scope and a drop-in example.
#
# Usage (works from any working directory):
#   ./install-service.sh                 install the binary next to this script
#   ./install-service.sh --binary PATH   install another binary
#   ./install-service.sh --no-enable     install only, do not enable or start
set -eu

# Resolve against the script, not the caller's working directory.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=$here/socktrail
unit=$here/packaging/socktrail.service
enable=yes
while [ $# -gt 0 ]; do
  case "$1" in
    --binary)
      if [ $# -lt 2 ]; then
        echo 'missing value for --binary' >&2
        exit 2
      fi
      binary=$2
      shift 2
      ;;
    --no-enable) enable=no; shift ;;
    -h|--help) sed -n '9,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# sudo only for the privileged commands, and not at all when already root.
as_root() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

if [ "$(uname -s)" != Linux ]; then
  echo 'socktrail supports Linux only' >&2
  exit 1
fi
# -x alone accepts a directory, so require a regular executable file.
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  echo "no executable at $binary; build it first with 'task build' or pass --binary PATH" >&2
  exit 1
fi
if [ ! -f "$unit" ]; then
  echo "no service template at $unit" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo 'systemd (systemctl) is required; install the binary by hand and run it with sudo instead' >&2
  exit 1
fi

as_root install -o root -g root -m 0755 "$binary" /usr/local/bin/socktrail
as_root install -o root -g root -m 0644 "$unit" /etc/systemd/system/socktrail.service
as_root systemctl daemon-reload

if [ "$enable" != yes ]; then
  echo 'installed without enabling; start it with: sudo systemctl enable --now socktrail.service'
elif systemctl is-active --quiet socktrail.service; then
  as_root systemctl enable socktrail.service
  # Upgrading a service that is already running: the new file is in place, but
  # only a restart picks it up, and whether to interrupt the collector is the
  # user's decision, so the script only points at the command.
  echo 'socktrail.service is already running; restart it to use the new binary:'
  echo '  sudo systemctl restart socktrail.service'
else
  as_root systemctl enable --now socktrail.service
  echo 'socktrail.service is enabled and started'
  echo 'socket: /run/socktrail/collector.sock (0660, group root)'
  echo 'a consumer in another account needs the group widened, see docs/user/usage.md'
fi
