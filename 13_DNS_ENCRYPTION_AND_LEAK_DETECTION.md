# DNS Encryption & Leak Detection

Everything so far assumes DNS itself is trustworthy and just checks whether it's *fast*
(`01_QUICK_CHECKLIST.md`, `05_AI_WORKLOAD_AND_LATENCY.md`). This doc is about the other axis:
plain UDP/53 DNS is unauthenticated and unencrypted — your ISP, anyone on the path, or anyone
on a shared/compromised segment can see every domain you resolve and, in the worse case, forge
answers. Fixing this cheaply, and then verifying it actually took, are two separate steps —
do both, because the fix silently not applying everywhere is the normal failure mode.

## 1. Fix it once, upstream — not per-device

If your network has more than one client machine, don't reach for per-device DNS-over-HTTPS/TLS
settings first. Find the resolver(s) your DHCP server(s) actually hand out — often just one or
two dnsmasq/router instances for an entire LAN — and encrypt *those*. Every client that gets its
DNS server from DHCP inherits the fix with zero per-device config, including phones, IoT
devices, and anything you don't control the OS of.

**Recipe (Debian/Ubuntu, dnsmasq as the resolver):**

```bash
apt install dnscrypt-proxy    # ships in Debian 12/13 and Ubuntu repos, no third-party repo needed
```

`/etc/dnscrypt-proxy/dnscrypt-proxy.toml` — minimum viable config:

```toml
listen_addresses = []          # empty = use systemd socket activation, see gotcha below
server_names = ['quad9-doh-ip4-port443-nofilter-pri', 'cloudflare']   # pick 2, see §2
ipv4_servers = true
ipv6_servers = false           # true only if you actually have a v6 route
require_dnssec = false         # true if you want validation and are OK with the extra failure mode
require_nolog = true
require_nofilter = true        # don't let a "security" resolver silently block domains you need
lb_strategy = 'p2'             # picks between the two lowest-latency servers, auto-failover
cache = true
cache_size = 10000
```

**This is different from the single-workstation case in `01_QUICK_CHECKLIST.md` §7**, which
specifically warns against chaining dnsmasq in front of dnscrypt-proxy — don't let that "why
not" scare you off the recipe below, it doesn't apply here. That warning is about
NetworkManager's `dns=dnsmasq` plugin, which tags the upstream it pushes to dnsmasq with the
physical interface (`nameserver 127.0.2.1#53(via enp5s0)`), and loopback traffic tagged with a
physical interface gets silently dropped — a NetworkManager-specific bug, not a property of
dnsmasq or of chaining itself. A **standalone `dnsmasq.service`** (the normal setup for a
router/DHCP server, not NetworkManager-managed) with a plain `server=127.0.2.1` directive has
no such tagging and chains to dnscrypt-proxy fine — this is exactly what's running in
production below, verified end-to-end from real client VMs. If you're setting this up on a
single laptop/desktop that already uses NetworkManager for its own DNS, follow §7's Option B
instead (point the system directly at `127.0.2.1`, skip the intermediate dnsmasq) — the two
docs solve different problems (one resolver serving a whole network vs. one machine's own
resolution) and use different mechanisms accordingly.

Then point dnsmasq at it instead of the public IPs directly:

```
# /etc/dnsmasq.d/upstream.conf
no-resolv
server=127.0.2.1     # the Debian package's default dnscrypt-proxy socket address+port
```

`systemctl restart dnscrypt-proxy dnsmasq` and test with `dig @<dnsmasq-ip> example.com` (or,
if `dig`/`nslookup` aren't installed, a raw UDP socket query — see the one-off script this repo
used, further down). Do this on **every** DHCP/dnsmasq instance on the network — if you have
more than one (a main router plus a secondary segment, for example), each is a separate leak
surface until it's converted too.

**Gotcha (Debian package, verified 2026-09):** the shipped `.deb` also installs a
`dnscrypt-proxy-resolvconf.service` that rewrites `/etc/resolv.conf`, which you don't want if
dnsmasq already has `no-resolv` (dnsmasq isn't reading that file, so the hook just adds a moving
part with no benefit). But `systemctl disable --now dnscrypt-proxy-resolvconf` also silently
drops the `dnscrypt-proxy.socket` unit out of `sockets.target.wants` — the service keeps
running *right now* off the still-active runtime socket, so nothing looks wrong, but it won't
come back after the next reboot. Always follow the disable with:

```bash
systemctl enable --now dnscrypt-proxy.socket
systemctl is-enabled dnscrypt-proxy.service dnscrypt-proxy.socket dnsmasq.service   # all three: enabled
```

## 2. Picking servers: reuse whatever latency data you already have

If you've already benchmarked plain resolvers (the RTT-per-resolver table this guide's methodology
produces — see `05_AI_WORKLOAD_AND_LATENCY.md`), don't re-derive server choice from scratch: the
same providers that won the plaintext race are almost always also the fastest over DoH, because
the extra cost is one extra TLS handshake to the same anycast endpoint, not a different network
path. In one real deployment: Quad9 and Cloudflare were the two fastest plain UDP resolvers
(2.5-7ms depending on egress path); after switching both to DoH, cold-start latencies were 3-15ms
— same order of magnitude, no meaningful regression, and now encrypted. `lb_strategy = 'p2'`
reproduces the old "query everyone, first response wins" behavior with just two servers instead
of four, without the extra outbound queries.

Run `dnscrypt-proxy -config /path/to/toml -check` before restarting the service — it validates
syntax **and** actually probes the configured `server_names`, printing measured latency for each.
If a name doesn't exist in the current public-resolvers list, this is where you find out, not at
2am when the service fails to start.

## 3. Verifying it actually applied

A config change on the resolver doesn't guarantee every client uses it. Two independent things
can go wrong: a device might have a hardcoded resolver (some IoT gear, some Android phones with
"Private DNS" manually pinned to a specific provider, a misconfigured VM with a static
`/etc/resolv.conf`), or a leftover config on the gateway/router host itself might resurrect an
old plaintext resolver behind your back (see the PPPoE `usepeerdns` case below).

**Method: capture at the choke points, not everywhere.** You don't need to sniff every host —
capture on the interfaces where all client traffic to the outside world necessarily crosses:

```bash
# On the resolver's own LAN-facing interface, excluding traffic to/from itself
# (that's the normal, expected client-to-local-resolver chatter):
tcpdump -i <lan-iface> -nn -q udp port 53 and not host <resolver-own-ip>

# On the router/gateway's WAN-facing interface(s), no exclusion needed —
# after the fix, the *only* DNS-shaped traffic that should leave to the internet
# is the resolver's own DoH (port 443, not port 53):
tcpdump -i <wan-iface> -nn -q udp port 53
```

Run each for ~30-60s during normal usage (or longer if the network is quiet at the moment).
Anything left over on the LAN-side capture is a client talking to some IP that isn't your local
resolver — that's your leak. Anything on the WAN-side capture over port 53 (as opposed to 443)
means *something* is still doing plaintext lookups, whether that's a client bypassing the local
resolver entirely, or the gateway host's own OS resolution (see below).

**A real leak found this way turned out to be an authoritative-NS lookup, not a privacy leak.**
One host was querying a specific IP directly on port 53 instead of the local resolver. The
target had no reverse-resolver PTR pointing to a recursive service — it resolved to
`<name>.ns.cloudflare.com`, i.e. an *authoritative* nameserver for a specific zone, not a public
recursive resolver. That's consistent with a DNS-propagation-check tool (an ACME/Let's-Encrypt
client verifying a TXT record, for example) deliberately bypassing caching resolvers to see the
authoritative answer directly — a legitimate, intentional pattern, not a bug. Don't reflexively
"fix" every plaintext hit; check what the destination actually is (`socket.gethostbyaddr()` /
reverse DNS) before treating it as a problem.

**A real leak found this way turned out to be intentional infrastructure monitoring.** A
different host was sending a steady trickle of plaintext queries to `8.8.8.8` and `1.1.1.1`
specifically. Grepping the local scripts for the literal IP found a WAN-failover health-check
script that deliberately targets two well-known, always-up public resolvers *by IP* — the point
of that specific check is to detect whether one of your two internet uplinks can reach the
outside world *at all*, independent of your own (now-encrypted, now-local) DNS stack. Encrypting
that traffic would have broken the check's own purpose. Same lesson: identify before "fixing."

**A real, actually-wrong leak found this way:** a router/gateway host's own `/etc/resolv.conf`
had the ISP's own DNS servers in it, left over from before a `usepeerdns` PPPoE option had been
disabled. The disable itself was correct and stopped *future* overwrites, but nobody had gone
back and fixed the file's *current* contents — it had been silently stale since the mode change,
just never triggering an obvious symptom because the primary uplink still happened to reach
those particular resolvers. The risk: those ISP resolvers didn't answer at all from the *other*
uplink on a dual-WAN setup, so a failover to the backup connection would have taken out DNS at
exactly the same moment as the primary link — the worst possible time to lose it. Lesson: when
you find a documented "we fixed this" note for a config regression, verify the *current file
contents* match, don't just check that the mechanism that caused it is disabled.

## 4. If you don't have `dig`/`nslookup` on a target host

Minimal environments (thin VM templates, containers) often lack DNS client tools entirely.
A 20-line raw UDP query in Python needs nothing but the standard library:

```python
import socket, struct, sys, time

def query(server, port, name):
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    header = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    packet = header + qname + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    t0 = time.time()
    s.sendto(packet, (server, port))
    data, _ = s.recvfrom(512)
    rtt = (time.time() - t0) * 1000
    ancount = struct.unpack('>H', data[6:8])[0]
    print(f"{name} via {server}:{port} -> rtt={rtt:.1f}ms answers={ancount}")

query(sys.argv[1], int(sys.argv[2]), sys.argv[3])
```

`python3 dnsq.py 127.0.2.1 53 example.com` — enough to confirm a resolver is alive and returning
answers without pulling in `dnspython` or waiting on a package install.

## 5. Android and other client-side opt-in encryption

Android (9+) has a system-wide **Private DNS** setting (Settings → Network & Internet → Private
DNS) that does DNS-over-TLS independent of whatever the network's DHCP hands out. Two distinct
cases:

- **Set to "Automatic":** the phone uses whatever DNS server DHCP gives it, in plaintext, on
  that local hop — meaning it already inherits the upstream encryption from §1 above with zero
  configuration, as long as it's on a network whose resolver you've fixed. The only exposure is
  the LAN-internal hop (phone → local resolver), which isn't traversing the ISP or the open
  internet.
- **Set explicitly to a DoT hostname** (`dns.quad9.net`, `1dot1dot1dot1.cloudflare-dns.com`,
  `family.cloudflare-dns.com`, etc.): the phone encrypts DNS **everywhere**, including off your
  network (mobile data, other people's Wi-Fi) — but it also bypasses your local resolver
  entirely, so any split-horizon/internal-domain resolution your local dnsmasq does won't apply
  to that device anymore. Worth doing for a phone that leaves the network often; redundant, with
  a minor trade-off, for one that mostly stays on a network you've already fixed at the gateway.
