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
# Every file comes from the release that is latest now.
tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/jimyag/socktrail/releases/latest)
tag=${tag##*/}
base="https://github.com/jimyag/socktrail/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -r "$tmp"' EXIT

curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && sha256sum -c --ignore-missing checksums.txt)
# The checksum only catches a damaged download. Releases after v0.0.1 carry
# a build provenance attestation, which proves the release workflow of this
# repository built the binary; gh 2.49 or later checks it once signed in.
if [ "$tag" != v0.0.1 ] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 && gh attestation --help >/dev/null 2>&1; then
  gh attestation verify "$tmp/$asset" --repo jimyag/socktrail
fi

install_dir=${SOCKTRAIL_INSTALL_DIR:-/usr/local/bin}
if [ -w "$install_dir" ]; then
  install -m 0755 "$tmp/$asset" "$install_dir/socktrail"
else
  sudo install -m 0755 "$tmp/$asset" "$install_dir/socktrail"
fi
echo "Installed $install_dir/socktrail"
