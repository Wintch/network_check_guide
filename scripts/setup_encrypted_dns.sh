#!/bin/bash
# setup_encrypted_dns.sh -- apply 01_QUICK_CHECKLIST.md section 7 "Option B" (local cache +
# DoH-encrypted DNS) to a Debian host whose network is managed by dhcpcd rather than
# NetworkManager. See that section for the reasoning, the measured numbers, and the two gotchas
# this script exists to get right.
#
#   sudo bash setup_encrypted_dns.sh
#
# Safe to re-run. Nothing that can break resolution happens without the previous step being
# verified first, and the system-DNS switch reverts itself if a real lookup fails afterwards.
set -u

BK=/root/dns-rollback-$(date +%Y%m%d-%H%M%S)
TOML=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
step() { echo; echo "== $*"; }
die() { echo "!! $*"; exit 1; }

[ "$(id -u)" = 0 ] || die "run me with sudo"
command -v dhcpcd >/dev/null || die "no dhcpcd here -- if this host uses NetworkManager, follow 01_QUICK_CHECKLIST.md section 7 Option B as written (nmcli), not this script"

mkdir -p "$BK"
cp -a /etc/resolv.conf /etc/dhcpcd.conf "$BK"/ 2>/dev/null
echo "rollback copies in $BK"

# A dependency-free DNS query: minimal Debian installs often have no dig/nslookup at all
# (13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md section 4).
cat > /tmp/dnsq.py <<'PY'
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
dnscrypt-proxy -config "$TOML" -check > /tmp/dnscrypt-check.log 2>&1
rc=$?
tail -20 /tmp/dnscrypt-check.log | sed 's/^/  /'
# A root-run -check leaves root-owned files in the cache dir; the service runs as
# _dnscrypt-proxy and would silently stop refreshing the resolver list. Hand them back.
chown -R _dnscrypt-proxy:nogroup /var/cache/dnscrypt-proxy /var/log/dnscrypt-proxy 2>/dev/null
[ $rc -eq 0 ] || die "dnscrypt-proxy -check failed (rc=$rc) -- nothing changed yet"

step "4/6  enable the service (and the socket the resolvconf hook likes to silently drop)"
systemctl disable --now dnscrypt-proxy-resolvconf >/dev/null 2>&1
# dhcpcd owns /etc/resolv.conf here, so the package's resolvconf hook is a second writer fighting
# it. Disabling that hook also yanks dnscrypt-proxy.socket out of sockets.target.wants without
# saying so -- everything keeps working until the next reboot. Re-enable it explicitly.
systemctl enable --now dnscrypt-proxy.socket || die "cannot enable dnscrypt-proxy.socket"
systemctl restart dnscrypt-proxy.service
sleep 2
systemctl is-enabled dnscrypt-proxy.service dnscrypt-proxy.socket

step "5/6  test the proxy directly, before touching system DNS"
python3 /tmp/dnsq.py 127.0.2.1 api.anthropic.com || die "127.0.2.1 is not answering -- system DNS left untouched"
python3 /tmp/dnsq.py 127.0.2.1 github.com || die "127.0.2.1 answered once but not twice -- system DNS left untouched"

step "6/6  point the system at it"
# `static` replaces the DHCP-supplied list outright. That is the point: a leftover second
# nameserver is a plaintext fallback glibc will happily use whenever the first is slow.
sed -i '/^static domain_name_servers=/d' /etc/dhcpcd.conf
printf '\n# encrypted DNS: dnscrypt-proxy (DoH) listens here -- see 01_QUICK_CHECKLIST.md section 7 Option B\nstatic domain_name_servers=127.0.2.1\n' >> /etc/dhcpcd.conf
# -n rebinds without releasing the lease, so this does not drop the SSH session we are in.
dhcpcd -n >/dev/null 2>&1
sleep 3
grep -q '127\.0\.2\.1' /etc/resolv.conf || printf '# rewritten by setup_encrypted_dns.sh\nnameserver 127.0.2.1\n' > /etc/resolv.conf

echo; echo "resolv.conf now:"; sed 's/^/  /' /etc/resolv.conf
if ! python3 -c 'import socket,sys; socket.getaddrinfo("api.anthropic.com",443)' 2>/dev/null; then
	echo "!! system resolution FAILED -- rolling back"
	cp -a "$BK/dhcpcd.conf" /etc/dhcpcd.conf
	cp -a "$BK/resolv.conf" /etc/resolv.conf
	dhcpcd -n >/dev/null 2>&1
	die "rolled back to $BK; dnscrypt-proxy left installed but unused"
fi

echo
echo "OK -- system resolution works through 127.0.2.1 (encrypted DoH + local cache)."
echo "Confirm the wire is encrypted:  ss -tn state established | grep -E '1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112'"
echo "Revert:  cp $BK/dhcpcd.conf /etc/dhcpcd.conf && cp $BK/resolv.conf /etc/resolv.conf && dhcpcd -n"
