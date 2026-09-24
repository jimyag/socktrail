#!/usr/bin/env bash
# Checks socktrail's probes on other kernels and architectures.
#
#   test/vm/run.sh [amd64|arm64] [kernel-name...]
#
# Boots each kernel of kernels.txt for the architecture, or only the named
# ones, in QEMU with an initramfs holding socktrail, the probes' root tests,
# Debian's openssl client and a Go init (init/main.go), and judges each run
# by the init's VM-RESULT line. amd64 uses KVM when /dev/kvm is writable;
# arm64 on an x86 host runs under TCG, much more slowly. Downloads are
# cached in $VM_CACHE (default ~/.cache/socktrail-vm) and logs are written
# to $VM_OUT (default $TMPDIR/socktrail-vm). Exits non-zero if any kernel
# fails or cannot be downloaded.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
arch=${1:-amd64}
shift || true
cache=${VM_CACHE:-$HOME/.cache/socktrail-vm}
out=${VM_OUT:-${TMPDIR:-/tmp}/socktrail-vm}
case $arch in
amd64)
	qemu=(qemu-system-x86_64)
	console=ttyS0
	native=x86_64
	;;
arm64)
	qemu=(qemu-system-aarch64 -machine virt)
	console=ttyAMA0
	native=aarch64
	;;
*)
	echo "usage: $0 [amd64|arm64] [kernel-name...]" >&2
	exit 2
	;;
esac
if [ -w /dev/kvm ] && [ "$(uname -m)" = "$native" ]; then
	qemu+=(-enable-kvm -cpu host)
	limit=600
else
	qemu+=(-cpu max)
	limit=3600
fi
mkdir -p "$cache" "$out"

# fetch MIRROR INDEX PATTERN DIR downloads the newest package whose name
# matches PATTERN from a Debian-style index into DIR and prints its path.
fetch() {
	local mirror=$1 index=$2 pattern=$3 dir=$4
	local list package file
	list="$cache/index-$(printf '%s' "$mirror/$index" | sha256sum | cut -c1-16).gz"
	if [ ! -s "$list" ] || [ -n "$(find "$list" -mmin +1440)" ]; then
		curl -fsSL --retry 3 -o "$list.part" "$mirror/$index"
		mv "$list.part" "$list"
	fi
	package=$(zcat "$list" | sed -n 's/^Package: //p' | grep -E "$pattern" | sort -V | tail -1)
	if [ -z "$package" ]; then
		echo "no package matches $pattern in $mirror/$index" >&2
		return 1
	fi
	file=$(zcat "$list" | awk -v RS= -v p="Package: $package" 'index($0, p "\n") == 1' | sed -n 's/^Filename: //p' | head -1)
	mkdir -p "$dir"
	if [ ! -s "$dir/${file##*/}" ]; then
		curl -fsSL --retry 3 -o "$dir/${file##*/}.part" "$mirror/$file"
		mv "$dir/${file##*/}.part" "$dir/${file##*/}"
	fi
	echo "$dir/${file##*/}"
}

# kernel NAME SOURCE... prints the path of the kernel image, downloading it.
kernel() {
	local name=$1 dir deb
	shift
	if [ "$1" = container ]; then
		# An RPM kernel: dnf fetches it inside the distribution's image, which
		# also has the tools to unpack it. Refreshed weekly.
		dir="$cache/kernel/$name"
		if [ ! -s "$dir/vmlinuz" ] || [ -n "$(find "$dir/vmlinuz" -mtime +7)" ]; then
			mkdir -p "$dir"
			docker run --rm "$2" bash -c "dnf -q -y install cpio dnf-plugins-core >/dev/null && cd /tmp &&
				dnf -q -y download $3 >/dev/null && rpm2cpio $3-*.rpm | cpio -idm --quiet && cat lib/modules/*/vmlinuz" </dev/null >"$dir/vmlinuz.part"
			mv "$dir/vmlinuz.part" "$dir/vmlinuz"
		fi
		echo "$dir/vmlinuz"
		return
	fi
	if [ "$1" = url ]; then
		deb="$cache/kernel/${2##*/}"
		if [ ! -s "$deb" ]; then
			mkdir -p "$cache/kernel"
			curl -fsSL --retry 3 -o "$deb.part" "$2"
			mv "$deb.part" "$deb"
		fi
	else
		deb=$(fetch "$1" "$2" "$3" "$cache/kernel")
	fi
	dir="${deb%.deb}"
	if [ ! -s "$dir/vmlinuz" ]; then
		mkdir -p "$dir"
		dpkg-deb --fsys-tarfile "$deb" | tar -x -C "$dir" --wildcards './boot/vmlinuz-*'
		mv "$dir"/boot/vmlinuz-* "$dir/vmlinuz"
	fi
	echo "$dir/vmlinuz"
}

# The initramfs: the init, socktrail and the probes' root tests built for the
# architecture, and a Debian userland for the openssl client.
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root"/{bin,data,dev,proc,sys,tmp}
(
	cd "$repo"
	export CGO_ENABLED=0 GOOS=linux GOARCH=$arch
	go build -o "$root/init" ./test/vm/init
	go build -o "$root/bin/socktrail" ./cmd/socktrail
	for package in probe sockstream capture conntrack; do
		go test -c -o "$root/bin/$package.test" "./internal/$package"
	done
)
cp "$repo/internal/quicinitial/testdata/rfc9001-client-initial.hex" "$root/data/quic-initial.hex"
for package in libc6 libssl3 openssl; do
	deb=$(fetch http://deb.debian.org/debian "dists/bookworm/main/binary-$arch/Packages.gz" "^$package\$" "$cache/userland-$arch")
	dpkg-deb -x "$deb" "$root"
done
rm -rf "${root:?}/usr/share"
(cd "$root" && find . | cpio -o -H newc --quiet | gzip -1) >"$out/initramfs-$arch.gz"

failed=0
# The list comes on fd 3: QEMU's serial console would read stdin.
while read -r name kernel_arch source <&3; do
	if [ -z "$name" ] || [ "${name:0:1}" = "#" ] || [ "$kernel_arch" != "$arch" ]; then
		continue
	fi
	if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qxF "$name"; then
		continue
	fi
	log="$out/$arch-$name.log"
	# shellcheck disable=SC2086 # The source is several words.
	if ! image=$(kernel "$name" $source); then
		echo "$name: kernel download failed"
		failed=1
		continue
	fi
	timeout "$limit" "${qemu[@]}" -m 2048 -smp 2 -nographic -no-reboot -kernel "$image" \
		-initrd "$out/initramfs-$arch.gz" -append "console=$console panic=-1 loglevel=3" </dev/null >"$log" 2>&1 || true
	verdict=$(grep -a -m1 '^VM-RESULT' "$log" | tr -d '\r' || true)
	if [[ $verdict == *" tests-failed=0 "* && $verdict == *" capture-dropped=0 "* &&
		$verdict == *"socktrail-ok=true"* && $verdict != *"openssl-sni-events=0 "* && $verdict != *" flows=0 "* ]]; then
		echo "$name: ok (${verdict#VM-RESULT })"
	else
		echo "$name: FAILED (${verdict:-no result}); log: $log"
		failed=1
	fi
done 3<"$repo/test/vm/kernels.txt"
exit $failed
