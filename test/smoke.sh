#!/usr/bin/env bash
# Takes a JSON snapshot of lo while making HTTP and OpenSSL TLS requests,
# then checks that the requests were captured and named, the OpenSSL probe
# saw the client process, and no packet was dropped. Needs root, curl, jq,
# openssl and python3.
#
#   sudo test/smoke.sh path/to/socktrail
set -euo pipefail

socktrail=$1
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=smoke.test \
	-keyout "$work/key.pem" -out "$work/cert.pem" -days 1 2>/dev/null
openssl s_server -accept 18443 -cert "$work/cert.pem" -key "$work/key.pem" -quiet </dev/null >/dev/null 2>&1 &
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 &
"$socktrail" --interface lo --duration 20s --limit 1000 --output json >"$work/snapshot.json" &
snapshot=$!
sleep 8 # The window opens once the probes are loaded; the requests fall inside it.
for _ in 1 2 3; do
	curl -fsS -o /dev/null -H 'Host: smoke.test' http://127.0.0.1:18080/
	openssl s_client -connect 127.0.0.1:18443 -servername smoke.test </dev/null >/dev/null 2>&1
done
wait "$snapshot"

jq '{flows: (.reports[0].flows | length), dropped: .reports[0].capture_dropped, openssl: .probes.openssl}' "$work/snapshot.json"
jq -e '.reports[0].capture_dropped == 0' "$work/snapshot.json" >/dev/null
jq -e 'any(.reports[0].flows[]; (.evidence.hosts["smoke.test"] // 0) > 0)' "$work/snapshot.json" >/dev/null ||
	{ echo "no HTTP flow with Host smoke.test" >&2; exit 1; }
# curl's connection closes within milliseconds, before its socket events
# arrive: the process and the kernel's RTT must still reach it.
jq -e 'any(.reports[0].flows[]; (.evidence.hosts["smoke.test"] // 0) > 0 and .client.name == "curl" and .rtt_source == "kernel")' "$work/snapshot.json" >/dev/null ||
	{ jq '.reports[0].flows[] | select((.evidence.hosts["smoke.test"] // 0) > 0) | {client, rtt_source, rtt_us, kernel_tcp}' "$work/snapshot.json" >&2; echo "the HTTP flow lacks curl as its client or the kernel's RTT" >&2; exit 1; }
jq -e 'any(.reports[0].flows[]; .evidence.sni == "smoke.test" and (.openssl_pids | length) > 0)' "$work/snapshot.json" >/dev/null ||
	{ echo "no TLS flow named smoke.test with an OpenSSL process" >&2; exit 1; }
echo "smoke test passed"
