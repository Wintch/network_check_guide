#!/bin/bash
# setup_encrypted_dns.sh -- apply 13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md section 6 "Option B"
# (local cache + DoH-encrypted DNS) to a Debian host whose network is managed by dhcpcd rather
# than NetworkManager. See that doc for the reasoning, the recommended dnscrypt-proxy settings
# (this script applies exactly those), and the gotchas this script exists to get right.
#
#   sudo bash setup_encrypted_dns.sh
#
# Safe to re-run. Nothing that can break resolution happens without the previous step being
# verified first, and the system-DNS switch reverts itself if a real lookup fails afterwards or
# if any nameserver other than 127.0.2.1 is still in resolv.conf.
set -u

# Paths are overridable so tests can run this against a sandbox instead of the real /etc.
BK=${BK_ROOT:-/root}/dns-rollback-$(date +%Y%m%d-%H%M%S)
TOML=${TOML:-/etc/dnscrypt-proxy/dnscrypt-proxy.toml}
DHCPCD_CONF=${DHCPCD_CONF:-/etc/dhcpcd.conf}
RESOLV_CONF=${RESOLV_CONF:-/etc/resolv.conf}
step() { echo; echo "== $*"; }
die() { echo "!! $*"; exit 1; }

[ "$(id -u)" = 0 ] || die "run me with sudo"
command -v dhcpcd >/dev/null || die "no dhcpcd here -- if this host uses NetworkManager, follow 13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md section 6 Option B as written (nmcli), not this script"

mkdir -p "$BK"
WORK=$(mktemp -d)
cp -a "$RESOLV_CONF" "$DHCPCD_CONF" "$BK"/ 2>/dev/null

# Rollback on ANY failing exit once armed (set -u aborts, failed die, signal), never on success.
ROLLBACK_ARMED=0
on_exit() {
	rc=$?
	rm -rf "$WORK"
	if [ "$rc" -ne 0 ] && [ "$ROLLBACK_ARMED" -eq 1 ]; then
		echo "!! exit $rc after changes started -- restoring files from $BK"
		[ ! -f "$BK/dhcpcd.conf" ] || cp -a "$BK/dhcpcd.conf" "$DHCPCD_CONF"
		[ ! -f "$BK/resolv.conf" ] || cp -a "$BK/resolv.conf" "$RESOLV_CONF"
		[ ! -f "$BK/dnscrypt-proxy.toml.orig" ] || cp -a "$BK/dnscrypt-proxy.toml.orig" "$TOML"
		dhcpcd -n >/dev/null 2>&1 || true
		systemctl restart dnscrypt-proxy.service >/dev/null 2>&1 || true
	fi
	exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "rollback copies in $BK"

# A dependency-free DNS query: minimal Debian installs often have no dig/nslookup at all
# (13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md section 4).
cat > "$WORK"/dnsq.py <<'PY'
import socket, struct, sys, time, random
srv, name = sys.argv[1], sys.argv[2]
q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
pkt = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) + q + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
t0 = time.perf_counter(); s.sendto(pkt, (srv, 53)); d, _ = s.recvfrom(1024)
ans = struct.unpack('>H', d[6:8])[0]
print(f"  {name} via {srv}: {(time.perf_counter()-t0)*1000:.1f}ms, {ans} answers")
sys.exit(0 if ans else 1)
PY

step "1/6  install dnscrypt-proxy"
if ! dpkg -s dnscrypt-proxy >/dev/null 2>&1; then
	DEBIAN_FRONTEND=noninteractive apt-get install -y dnscrypt-proxy || die "apt install failed"
else
	echo "  already installed"
fi
cp -a "$TOML" "$BK/dnscrypt-proxy.toml.orig"
ROLLBACK_ARMED=1   # from here on, state is modified: any failing exit restores $BK

step "2/6  configure resolvers (Cloudflare + Quad9 over DoH, p2 load balancing, local cache)"
# Edit the shipped toml in place rather than replacing it: Debian's default carries the
# [sources] block that fetches and minisign-verifies the public-resolvers list, and without it
# `server_names` cannot be resolved to an actual endpoint.
python3 - "$TOML" <<'PY'
import re, sys
path = sys.argv[1]
want = {
    "server_names": "['cloudflare', 'quad9-doh-ip4-port443-nofilter-pri']",
    "ipv4_servers": "true",
    "ipv6_servers": "false",   # flip to true only with a working IPv6 route
    "require_dnssec": "false",
    "require_nolog": "true",
    # nofilter on both: a "security" resolver silently blocking a CDN is a worse, much harder to
    # diagnose failure than no filtering at all. Note this rejects the quad9 *filter* variants.
    "require_nofilter": "true",
    "lb_strategy": "'p2'",     # keeps the two lowest-latency servers warm, fails over on its own
    "cache": "true",
    "cache_size": "10000",
}
lines = open(path).read().splitlines()
head = next((i for i, l in enumerate(lines) if re.match(r"\s*\[", l)), len(lines))
seen = set()
for i in range(head):
    m = re.match(r"\s*#?\s*([a-z_0-9]+)\s*=", lines[i])
    if m and m.group(1) in want and m.group(1) not in seen:
        seen.add(m.group(1))
        lines[i] = f"{m.group(1)} = {want[m.group(1)]}"
for k, v in want.items():
    if k not in seen:
        lines.insert(head, f"{k} = {v}")
        head += 1
open(path, "w").write("\n".join(lines) + "\n")
print("  set: " + ", ".join(sorted(want)))
PY

step "3/6  validate config and probe the chosen resolvers"
# -check parses the file AND actually reaches each server_name, printing its measured latency. A
# name that no longer exists in the public list surfaces here, not at the next reboot.
dnscrypt-proxy -config "$TOML" -check > "$WORK"/dnscrypt-check.log 2>&1
rc=$?
tail -20 "$WORK"/dnscrypt-check.log | sed 's/^/  /'
# A root-run -check leaves root-owned files in the cache dir; the service runs as
# _dnscrypt-proxy and would silently stop refreshing the resolver list. Hand them back.
chown -R _dnscrypt-proxy:nogroup /var/cache/dnscrypt-proxy /var/log/dnscrypt-proxy 2>/dev/null
[ $rc -eq 0 ] || die "dnscrypt-proxy -check failed (rc=$rc) -- rolling back the toml edit"

step "4/6  enable the service (and the socket the resolvconf hook likes to silently drop)"
systemctl disable --now dnscrypt-proxy-resolvconf >/dev/null 2>&1
# dhcpcd owns /etc/resolv.conf here, so the package's resolvconf hook is a second writer fighting
# it. Disabling that hook also yanks dnscrypt-proxy.socket out of sockets.target.wants without
# saying so -- everything keeps working until the next reboot. Re-enable it explicitly.
systemctl enable --now dnscrypt-proxy.socket || die "cannot enable dnscrypt-proxy.socket"
systemctl restart dnscrypt-proxy.service
sleep 2
systemctl is-enabled dnscrypt-proxy.service dnscrypt-proxy.socket || true

step "5/6  test the proxy directly, before touching system DNS"
python3 "$WORK"/dnsq.py 127.0.2.1 example.com || die "127.0.2.1 is not answering -- system DNS left untouched"
python3 "$WORK"/dnsq.py 127.0.2.1 github.com || die "127.0.2.1 answered once but not twice -- system DNS left untouched"

step "6/6  point the system at it"
# `static` replaces the DHCP-supplied IPv4 list outright. That is the point: a leftover second
# nameserver is a plaintext fallback glibc will happily use whenever the first is slow.
# The line must sit at TOP LEVEL, before the first interface/profile/ssid/arping block: in
# dhcpcd.conf an option after such a line only applies to that block.
python3 - "$DHCPCD_CONF" <<'PY'
import re, sys
path = sys.argv[1]
OPT = re.compile(r"\s*static\s+domain_name_servers\s*=")
BLOCK = re.compile(r"\s*(interface|profile|ssid|arping)\s")
lines = open(path).read().splitlines()
first_block = next((i for i, l in enumerate(lines) if BLOCK.match(l)), len(lines))
# Drop only top-level copies (re-runs stay idempotent); a copy inside a block is left alone,
# but reported, because it overrides the top-level one for that interface.
for i in range(first_block, len(lines)):
    if OPT.match(lines[i]):
        print(f"  WARNING: {path}:{i + 1} sets domain_name_servers inside an interface/profile block "
              "and overrides the top-level line for it -- edit that line by hand")
MARK = "# encrypted DNS: dnscrypt-proxy (DoH) listens here"
top = [l for l in lines[:first_block] if not OPT.match(l) and not l.startswith(MARK)]
rest = lines[first_block:]
while top and not top[-1].strip():
    top.pop()
new = ["", MARK + " -- see 13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md section 6",
       "static domain_name_servers=127.0.2.1"]
out = top + new + ([""] + rest if rest else [])
open(path, "w").write("\n".join(out) + "\n")
PY
# -n rebinds without releasing the lease, so this does not drop the SSH session we are in.
dhcpcd -n >/dev/null 2>&1
sleep 3
if ! awk '$1 == "nameserver" && $2 == "127.0.2.1" { f = 1 } END { exit !f }' "$RESOLV_CONF"; then
	echo "  dhcpcd did not publish 127.0.2.1 in $RESOLV_CONF -- writing it directly (dhcpcd may overwrite this at the next renewal)"
	printf '# rewritten by setup_encrypted_dns.sh\nnameserver 127.0.2.1\n' > "$RESOLV_CONF"
fi

echo; echo "resolv.conf now:"; sed 's/^/  /' "$RESOLV_CONF"
# Every nameserver must be the local proxy. One leftover entry is a plaintext fallback.
OTHERS=$(awk '$1 == "nameserver" && $2 != "127.0.2.1" { print $2 }' "$RESOLV_CONF")
if [ -n "$OTHERS" ]; then
	echo "  still listed besides 127.0.2.1: $(echo $OTHERS)"
	echo "  IPv6 Router Advertisements (RDNSS) and DHCPv6 can add servers that 'static domain_name_servers' does not cover."
		echo "  Add 'nooption nd_rdnss' and 'nooption dhcp6_name_servers' to the global section of $DHCPCD_CONF (names vary by dhcpcd version: dhcpcd -V) -- see 13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md section 6."
	die "resolv.conf still has plaintext nameservers -- rolled back to $BK"
fi
if ! python3 -c 'import socket,sys; socket.getaddrinfo("example.com",443)' 2>/dev/null; then
	die "system resolution FAILED -- rolled back to $BK; dnscrypt-proxy left installed but unused"
fi
ROLLBACK_ARMED=0

echo
echo "OK -- system resolution works through 127.0.2.1 (encrypted DoH + local cache), and it is the only nameserver."
echo "Note: if the network later starts handing out IPv6 DNS (RDNSS/DHCPv6), re-check resolv.conf; see the doc above."
echo "Confirm the wire is encrypted:  ss -tn state established | grep -E '1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112'"
echo "Revert:  cp $BK/dhcpcd.conf $DHCPCD_CONF && cp $BK/resolv.conf $RESOLV_CONF && dhcpcd -n"
