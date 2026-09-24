#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
  echo 'socktrail supports Linux only' >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo 'unsupported architecture' >&2; exit 1 ;;
esac

asset="socktrail_linux_$arch"
base='https://github.com/jimyag/socktrail/releases/latest/download'
tmp=$(mktemp -d)
trap 'rm -r "$tmp"' EXIT

curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && sha256sum -c --ignore-missing checksums.txt)

install_dir=${SOCKTRAIL_INSTALL_DIR:-/usr/local/bin}
if [ -w "$install_dir" ]; then
  install -m 0755 "$tmp/$asset" "$install_dir/socktrail"
else
  sudo install -m 0755 "$tmp/$asset" "$install_dir/socktrail"
fi
echo "Installed $install_dir/socktrail"
