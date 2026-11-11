# DNS Encryption & Leak Detection

Everything so far assumes DNS itself is trustworthy and just checks whether it's *fast*
(`01_QUICK_CHECKLIST.md`, `05_AI_WORKLOAD_AND_LATENCY.md`). This doc is about the other axis:
plain UDP/53 DNS is unauthenticated and unencrypted — your ISP, anyone on the path, or anyone
on a shared/compromised segment can see every domain you resolve and, in the worse case, forge
answers. Fixing this cheaply, and then verifying it actually took, are two separate steps —
do both, because the fix silently not applying everywhere is the normal failure mode.

| You want to… | Go to |
|---|---|
| Encrypt DNS for a whole LAN (every client inherits it) | §1 |
| Choose which resolvers to use | §2 |
| Prove nothing still leaves in plaintext | §3 |
| Query a resolver on a host with no `dig`/`nslookup` | §4 |
| Cache and encrypt DNS on **one** machine (NetworkManager or dhcpcd) | §6 (script: `scripts/setup_encrypted_dns.sh`) |
| Phones and other client-side opt-in encryption | §5 |
| Why systemd-resolved DoT and dnsmasq-in-front-of-dnscrypt break | §7 |

## The recommended configuration (one place)

Everything in this doc and `scripts/setup_encrypted_dns.sh` uses the same `dnscrypt-proxy`
settings:

```toml
server_names = ['cloudflare', 'quad9-doh-ip4-port443-nofilter-pri']   # pick 2, see §2
ipv4_servers = true
ipv6_servers = false           # true only if you actually have a v6 route
require_dnssec = false         # true if you want validation and are OK with the extra failure mode
require_nolog = true
require_nofilter = true        # don't let a "security" resolver silently block domains you need
lb_strategy = 'p2'             # random pick between the two lowest-latency servers, fails over on error
cache = true
cache_size = 10000
```

Edit the shipped `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` **in place** (the script does) rather
than replacing it: Debian's default carries the `[sources]` block that fetches and verifies the
public-resolvers list, and without it `server_names` cannot be turned into an endpoint. Leave
`listen_addresses` as the package ships it — Debian listens on `127.0.2.1:53` via systemd socket
activation (deliberately not `127.0.0.1`, so it can coexist with another local resolver).

**Filtering variant (optional).** If you *want* malware-domain blocking, use
`quad9-doh-ip4-port443-filter-pri` (Quad9's filtered resolver, the one behind `9.9.9.9`) and set
`require_nofilter = false`. The trade-off, stated once: a filtering resolver can block a domain
you legitimately need, and that failure is much harder to diagnose than the absence of
filtering — which is why the default above is unfiltered.

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

Configure `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` as in "The recommended configuration"
above, then point dnsmasq at it instead of the public IPs directly:

```
# /etc/dnsmasq.d/upstream.conf
no-resolv
server=127.0.2.1     # the Debian package's default dnscrypt-proxy socket address+port
```

`systemctl restart dnscrypt-proxy dnsmasq` and test with `dig @<dnsmasq-ip> example.com` (or,
if `dig`/`nslookup` aren't installed, see §4). Do this on **every** DHCP/dnsmasq instance on the
network — if you have more than one (a main router plus a secondary segment, for example), each
is a separate leak surface until it's converted too.

**Chaining dnsmasq in front of dnscrypt-proxy is fine here, unlike on a single
NetworkManager-managed workstation (§7).** That warning is about NetworkManager's `dns=dnsmasq`
plugin, which tags the upstream it pushes to dnsmasq with the physical interface
(`nameserver 127.0.2.1#53(via <iface>)`), and loopback traffic tagged with a physical interface
gets silently dropped — a NetworkManager-specific bug, not a property of dnsmasq or of
chaining. A **standalone `dnsmasq.service`** (the normal setup for a router/DHCP server) with a
plain `server=127.0.2.1` directive has no such tagging and chains to dnscrypt-proxy fine. The two
cases solve different problems (one resolver serving a network vs. one machine's own
resolution) and use different mechanisms accordingly.

**Gotcha (Debian package):** the shipped `.deb` also installs a
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

**Gotcha (root-run `-check`):** `dnscrypt-proxy -config ... -check` run as root leaves
root-owned files in `/var/cache/dnscrypt-proxy`. The Debian service runs as `_dnscrypt-proxy`
and then can't refresh the signed resolver list; it keeps working off what's cached, so this
surfaces days later as a stale list. Follow any root-run `-check` with
`chown -R _dnscrypt-proxy:nogroup /var/cache/dnscrypt-proxy /var/log/dnscrypt-proxy`.

## 2. Picking servers: speed vs. anonymity

The resolvers you'd reach for trade off latency against how much they (and anyone watching the
wire) learn about every domain you touch. Roughly fastest-to-most-private:

> **Scope and review date.** The "Typical latency" column is general, from memory, and **not
> measured on your network** — region and PoP placement change it a lot. The privacy column was
> checked on **2026-10-02** against each provider's own published policy, listed under the
> table; providers change policies, so re-read them before relying on this. Where a claim could
> not be confirmed it is marked *(unverified)*.

| Resolver | Typical latency | Privacy trade-off |
|---|---|---|
| **Your ISP's default** | Usually lowest (topologically closest hop) | Worst: plaintext UDP/53 by default, ISP can log/sell/inject and is the easiest party to subpoena |
| **Google `8.8.8.8`** | Very fast, huge anycast footprint | Logs IP + queries temporarily (24-48 h, longer only for security/abuse), then keeps anonymized, location-level aggregates [^g] |
| **Cloudflare `1.1.1.1`** | Fast; often among the lowest in public benchmarks such as DNSPerf *(unverified, varies by region)* | Deletes resolver logs within 25 h, truncates source IPs, keeps aggregates for Radar; states it is audited by a top-four accounting firm [^c]; supports DoH/DoT |
| **Quad9 `9.9.9.9`** | Often a few ms slower than Cloudflare *(unverified, varies by region)* | Swiss foundation; states it does not retain client IPs (held in RAM only to answer) and keeps only aggregate counters; `9.9.9.9` blocks known-malicious domains, the unfiltered endpoint does not [^q] |
| **Mullvad DoH (`dns.mullvad.net`)** | Similar to Quad9, sometimes a bit slower (fewer PoPs) *(unverified)* | Open to non-customers [^m]; its no-logging claim is *(unverified)* — the DNS help page does not state a logging policy, so check Mullvad's privacy policy; sensible if you also tunnel through their VPN so DNS and egress traffic stay together |
| **DNS over Tor / random per-query resolver** | Real latency cost — tens to hundreds of ms extra | Only worth it against a well-resourced/state-level adversary; overkill for "keep a coding session responsive" |

[^g]: https://developers.google.com/speed/public-dns/privacy
[^c]: https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/
[^q]: https://quad9.net/privacy/policy/
[^m]: https://mullvad.net/en/help/dns-over-https-and-dns-over-tls

The recommended configuration uses **Cloudflare + Quad9 (unfiltered)**: both are usually among
the faster options, both publish a short retention policy (above), and splitting across two
operators means neither sees all your queries. That is a judgement, not a measurement of your
network. If you'd rather avoid a US-based company entirely, swap in **Mullvad's DoH**; the cost
is a handful of milliseconds, not perceptible in interactive use. Avoid relying on your ISP's
default resolver if you care about privacy at all — it's fast because it's unencrypted and
minimally accountable, not because it's doing anything clever.

**Benchmark from your own network** before picking — PoP placement varies a lot by region:

```bash
for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
  echo -n "$r: "; dig @$r example.com +tries=1 +time=2 | grep "Query time"
done
```

Use `dig`, not `ping`: even the "fast" public resolvers show real jitter (a huge anycast fleet
can route your query to a farther backend than the ICMP-responding edge node, so a quick
`ping 8.8.8.8` doesn't guarantee consistent DNS latency).

Plain-UDP benchmarking is also an imperfect predictor of DoH latency for the *same* provider:
different anycast PoPs can answer :53 and :443, so a resolver that is slow over UDP may be fast
over DoH (or the reverse), though the providers that win the plaintext race usually still win
over DoH — the extra cost is one TLS handshake to the same kind of endpoint. Let
`dnscrypt-proxy`'s own probe settle it after the switch rather than pre-selecting from a `dig`
table: `dnscrypt-proxy -config /path/to/toml -check` validates syntax **and** probes every
configured `server_names`, printing the measured latency of each, and
`journalctl -u dnscrypt-proxy | grep "lowest initial latency"` shows which it settled on. If a
name doesn't exist in the current public-resolvers list, `-check` is where you find out, not
at 2am when the service fails to start. (The `-check` root-ownership gotcha is in §1.)

`lb_strategy = 'p2'` makes dnscrypt-proxy pick randomly between the two lowest-latency servers
for each query and fail over on errors. It does **not** send each query to both and take the
first answer; the benefit is that a second, already-warm server is always available.

## 3. Verifying it actually applied

A config change on the resolver doesn't guarantee every client uses it. Two independent things
can go wrong: a device might have a hardcoded resolver (some IoT gear, some Android phones with
"Private DNS" manually pinned to a specific provider, a VM with a static `/etc/resolv.conf`),
or a leftover config on the gateway/router host itself might resurrect an old plaintext
resolver behind your back (see the triage list below).

**Method: capture at the choke points, not everywhere.** You don't need to sniff every host —
capture on the interfaces where all client traffic to the outside world necessarily crosses.
Match both port 53 (UDP *and* TCP: truncated or large answers retry over TCP) and port 853
(DNS-over-TLS that bypasses your proxy):

```bash
# On the resolver's own LAN-facing interface, excluding traffic to/from itself
# (that's the normal, expected client-to-local-resolver chatter):
tcpdump -i <lan-iface> -nn -q '(port 53 or port 853) and not host <resolver-own-ip>'

# On the router/gateway's WAN-facing interface(s), no exclusion needed —
# after the fix, the *only* DNS-shaped traffic that should leave to the internet
# is the resolver's own DoH (port 443, not port 53 or 853):
tcpdump -i <wan-iface> -nn -q 'port 53 or port 853'

# On a single machine: anything not going to the local proxy
sudo tcpdump -i any -nn -q '(port 53 or port 853) and not host 127.0.2.1'
```

Run each for ~30-60s during normal usage (or longer if the network is quiet at the moment).
Anything left over on the LAN-side capture is a client talking to some IP that isn't your local
resolver — that's your leak. Anything on the WAN-side capture over port 53 or 853 means
*something* is still doing plaintext lookups, whether that's a client bypassing the local
resolver entirely, or the gateway host's own OS resolution.

Seeing the DoH connection is the positive proof that encryption is in use, but it is not
proof of *no leak* (an absence of `:53` in `ss` proves nothing, since `ss -tn` lists TCP only
and most plaintext DNS is UDP). Resolve a few never-queried names and catch the connection
while it's up (DoH connections close quickly when idle, so an empty result on a quiet host
means nothing):

```bash
ss -tn state established | grep -E '1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112'   # expect :443
```

**Triage a hit before "fixing" it.** Example: the capture shows a client sending queries to
`198.51.100.7:53` instead of your resolver. Identify the destination first
(`dig -x 198.51.100.7`, or `socket.gethostbyaddr()`), then find the sender
(`ss -upn`, or grep your scripts and cron jobs for the literal IP). A hit is one of:

- **Intentional, but still plaintext.** An authoritative-nameserver lookup (the reverse name
  ends in something like `ns.example.net`) is typical of an ACME/DNS-propagation checker
  deliberately bypassing caching resolvers. Likewise a health-check script that pins
  `8.8.8.8`/`1.1.1.1` by IP so it can test uplink reachability independent of your DNS stack —
  encrypting that would defeat its purpose. Neither is a bug, but both are visible on the wire,
  so decide knowingly. Don't reflexively "fix" it.
- **Actually wrong.** A gateway/server whose own `/etc/resolv.conf` still lists old DNS servers
  (for example left over from a previous DHCP or PPP lease after the option that wrote them was
  disabled). Disabling the mechanism stops *future* overwrites but does not repair the file's
  *current* contents, so it can stay stale for months until a failover or outage exposes it.
  When a "we fixed this" note exists, verify the current file contents, not just that the
  cause is disabled.
- **A hardcoded client** (IoT device, browser or phone with its own resolver): decide whether to
  reconfigure it or redirect/block outbound :53 and :853 at the gateway.

## 4. If you don't have `dig`/`nslookup` on a target host

Minimal environments (thin VM templates, containers) often lack DNS client tools entirely. A
stdlib-only Python UDP query is embedded in `scripts/setup_encrypted_dns.sh` (the `dnsq.py`
heredoc) so the code lives in one place. Extract and use it with:

```bash
awk "/dnsq.py <<'PY'/{f=1;next} /^PY\$/{f=0} f" scripts/setup_encrypted_dns.sh > dnsq.py
python3 dnsq.py 127.0.2.1 example.com     # <server> <name>; exits 0 only if it got answers
```

That is enough to confirm a resolver is alive and returning answers without pulling in
`dnspython` or waiting on a package install.

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

## 6. A single machine: local cache, and whether to encrypt it

Use this for one workstation or server, as opposed to §1's network-wide resolver.

**Conclusion first:** most systems have no local caching resolver by default, so every
lookup — even a repeat of the same domain seconds later — pays full round-trip latency to
whichever upstream you picked in §2. Fix it with one of these two setups, not both:

| Goal | Use | Skip |
|---|---|---|
| Just caching, plaintext is fine | **dnsmasq** via NetworkManager's plugin (Option A) | systemd-resolved, unbound (see below) |
| Caching **and** the query itself encrypted (DoT/DoH) | **dnscrypt-proxy** with the recommended configuration (Option B; has its own cache built in) | systemd-resolved (can break on Debian 13, §7); don't also run NetworkManager's dnsmasq in front of it (breaks, §7) |

Check what you currently have:

```bash
cat /etc/resolv.conf   # nameserver 127.x.x.x usually means a local cache already exists
ps aux | grep -E "dnsmasq|dnscrypt-proxy|unbound|nscd" | grep -v grep
```

### Option A — caching only: dnsmasq via NetworkManager

Simplest path if you don't need encryption: usually a one-package install
(`dnsmasq-base`), NetworkManager manages the process lifecycle and derives the upstream
servers from the connection's own DNS setting, and it survives network switches/VPN.
`systemd-resolved` gives the same caching benefit but pulls in more moving parts if it isn't
already your distro's default (a new package plus re-pointing `/etc/resolv.conf` at its stub);
`unbound` is a full validating recursive resolver, worth it only if you want to stop depending
on any third-party resolver at all — overkill for "just cache what the upstream already gave me."

`ipv4.dns` on a DHCP connection **adds to** the DHCP-supplied servers; it does not replace
them. Add `ignore-auto-dns` if you want only your choice upstream:

```bash
sudo nmcli connection modify "<your connection name>" \
  ipv4.dns "9.9.9.9" ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes
sudo mkdir -p /etc/NetworkManager/conf.d
sudo tee /etc/NetworkManager/conf.d/dns-dnsmasq.conf > /dev/null <<'EOF'
[main]
dns=dnsmasq
EOF
sudo systemctl restart NetworkManager   # brief (1-2s) network blip while it reloads
```

Verify: `grep -v '^#' /etc/resolv.conf` → `nameserver 127.0.0.1`. Confirm the cache is live by
resolving the same domain twice — the second call should drop to sub-millisecond:

```bash
dig example.com | grep "Query time"   # first: real upstream latency
dig example.com | grep "Query time"   # second: ~0 msec, served from local cache
```

Revert: delete `/etc/NetworkManager/conf.d/dns-dnsmasq.conf`, then
`sudo nmcli connection modify "<your connection name>" ipv4.dns "" ipv4.ignore-auto-dns no ipv6.ignore-auto-dns no`
and restart NetworkManager.

### Option B — caching + encryption: dnscrypt-proxy → DoH

Recommended if you want the query itself unreadable in transit, not just a better resolver
privacy policy. Plain `dig @9.9.9.9` (Option A, or any router/DHCP-provided resolver) is
ordinary UDP/53 — readable by anything on the path, ISP included, regardless of which
resolver you pick. Encryption requires DoT (port 853) or DoH (port 443), which Quad9 and
Cloudflare support but `dnsmasq` cannot speak.

`dnscrypt-proxy` is the tool to reach for over the alternatives: it's in Debian's own repos
(no third-party repo needed), ships with Quad9 and Cloudflare already in its resolver list, and
— unlike `cloudflared` (not packaged for Debian, defaults to Cloudflare's own resolver, and
DNS-proxying is a side feature of a tunneling tool) — it's purpose-built for "encrypt to the
resolver I choose."

```bash
sudo apt-get install -y dnscrypt-proxy
# edit /etc/dnscrypt-proxy/dnscrypt-proxy.toml in place: set the keys from
# "The recommended configuration" at the top of this doc
sudo systemctl restart dnscrypt-proxy.socket dnscrypt-proxy.service
dig @127.0.2.1 example.com   # sanity check before touching system DNS
```

The exact resolver names come from
`grep -i "^## quad9" -A3 /var/cache/dnscrypt-proxy/public-resolvers.md` (fetched and cached
automatically on first install/start). Verify the service picked the resolvers you configured,
not the package's `cloudflare` default alone, and check the live connection, not just the logs:

```bash
journalctl -u dnscrypt-proxy | grep -i -E "quad9|cloudflare"   # "(DoH) OK" against your names
dig @127.0.2.1 <a-fresh-never-queried-domain>
ss -tn state established | grep -E '1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112'   # expect :443
```

Point the system at it directly — no dnsmasq in front. `ignore-auto-dns` is essential: without
it NetworkManager keeps the router's/ISP's plaintext servers in the list *after* `127.0.2.1`,
and glibc falls back to them whenever the first entry is slow to answer, silently
un-encrypting those queries.

```bash
sudo nmcli connection modify "<your connection name>" \
  ipv4.dns "127.0.2.1" ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes
sudo systemctl restart NetworkManager
grep -v '^#' /etc/resolv.conf   # must list ONLY: nameserver 127.0.2.1
```

If `resolv.conf` still lists any other nameserver, you still have a plaintext fallback; also
check for a second active connection (Wi-Fi + Ethernet) that needs the same settings.

Revert: `sudo nmcli connection modify "<your connection name>" ipv4.dns "" ipv4.ignore-auto-dns no ipv6.ignore-auto-dns no`,
restart NetworkManager.

### Option B on a `dhcpcd`-managed host (no NetworkManager)

A headless/server-ish Debian box often has no NetworkManager at all — `cat /etc/resolv.conf`
says `# Generated by dhcpcd from <iface>.dhcp` and `nmcli connection show --active` lists only
`lo`. Everything above still applies; only the last step, pointing the system at `127.0.2.1`,
changes. Use dhcpcd's own static override instead of `nmcli`:

```bash
# /etc/dhcpcd.conf, at TOP LEVEL, i.e. BEFORE the first "interface"/"profile"/"ssid" line:
static domain_name_servers=127.0.2.1
```

Position matters: in `dhcpcd.conf`, options after an `interface <name>` line apply only to
that interface, so a line appended at the end of a file that has interface blocks would not be
global. `static` replaces the DHCP-supplied list outright rather than prepending to it — the
same goal `ignore-auto-dns` serves on NetworkManager. (A `/etc/resolv.conf.head` with
`nameserver 127.0.2.1` in it looks like the same fix and isn't: it prepends, leaving the DHCP
entries underneath.)

Apply it with **`sudo dhcpcd -n`** (rebind), not `systemctl restart dhcpcd`: `-n` re-reads the
config without releasing the lease, so it doesn't drop the SSH session you're running it from.

**IPv6 can still add servers.** `static domain_name_servers` only overrides the IPv4 DHCP
option. dhcpcd also processes IPv6 Router Advertisements (RDNSS) and DHCPv6, and either can add
plaintext nameservers to `resolv.conf` on an IPv6-enabled network. After applying, check
`grep -v '^#' /etc/resolv.conf`; if anything other than `127.0.2.1` is listed, add
the following to the same global section of `dhcpcd.conf` and rebind:

```
nooption nd_rdnss               # ignore DNS servers announced in Router Advertisements
nooption dhcp6_name_servers     # ignore DNS servers from DHCPv6
```

`man dhcpcd.conf` says ND options take an `nd_` prefix and DHCPv6 options a `dhcp6_` prefix in
`nooption`; the exact variable names vary by dhcpcd version, so confirm them with
`dhcpcd -V | grep -iE 'rdnss|name_servers'`. The blunt fallbacks are `noipv6rs` (ignore Router
Advertisements) or `noipv6` (ignore RAs and DHCPv6), but both also stop IPv6 address
autoconfiguration on that interface, so use them only if you do not need IPv6 there.

`scripts/setup_encrypted_dns.sh` does the whole dhcpcd sequence non-interactively, verifies
`127.0.2.1` answers *before* touching system DNS, inserts the static line at top level, and
**fails (and rolls back) if any nameserver other than `127.0.2.1` is still in `resolv.conf`
afterwards**. It rolls itself back from `/root/dns-rollback-<stamp>/` on **any** failing exit
once it has started modifying anything (a failed `dnscrypt-proxy -check`, a failed probe, a
failed final check or lookup, a signal) — a normal exit never restores. It restores
`dhcpcd.conf`, `resolv.conf` and the original `dnscrypt-proxy.toml`; it does not uninstall the
package. The config paths can be redirected with `BK_ROOT`, `TOML`, `DHCPCD_CONF` and
`RESOLV_CONF`, which is how the tests run it against a sandbox.

**What to expect, illustrative** (one example gigabit link; your numbers will differ):

| | before (gateway + `9.9.9.9`, plaintext, no local cache) | after (dnscrypt-proxy, Cloudflare + Quad9 DoH, `p2`) |
|---|---|---|
| Cold lookup, p50 | 35.6 ms | 30.1 ms |
| Cold lookup, worst of 5 | 406 ms | 197 ms |
| Repeat lookup | 1.6 ms | **0.0-0.2 ms** |
| `curl time_namelookup` | 3.5 ms | **0.8 ms** |

**Cold lookups do not get meaningfully faster, and shouldn't be sold as if they do** — a cold
lookup is dominated by the upstream's own recursion to the authoritative nameservers, which is
the same work no matter who you ask or how the question is encrypted. What actually improves is
the *tail* (a resolver having a bad moment no longer costs 400 ms, because `lb_strategy = 'p2'`
has a second one warm), repeat lookups (in-process cache, effectively free), and the part that
was the point: the queries are no longer readable on the wire.

Then prove it with §3: a row on `:443` is the encrypted connection, and
`tcpdump '(port 53 or port 853) and not host 127.0.2.1'` should stay silent.

`scripts/quick_check.py`'s cache detection works with either option unchanged — it flags any
loopback nameserver (`127.x.x.x`), not just `127.0.0.1`.

## 7. Why not: two tempting setups that break

### systemd-resolved with DoT

Tempting because it needs no extra proxy (`DNSOverTLS=yes` plus `DNS=9.9.9.9#dns.quad9.net`
in `/etc/systemd/resolved.conf.d/`), but on Debian 13 (systemd 257) it failed outright when
added fresh: its D-Bus interface never activated, which silently broke NetworkManager's
ability to hand it a DNS server, leaving it with none configured and `REFUSED` on every query.
**Impact:** total DNS outage, and installing the package also symlinks `/etc/resolv.conf` to its
stub, so disabling the service alone leaves DNS dead until you `apt purge systemd-resolved` and
let NetworkManager rewrite `resolv.conf`. If `systemd-resolved` is *already* your distro's
working default (`resolvectl status` succeeds before you touch anything), adding
`DNSOverTLS=yes` is fine — the failure is specific to bolting it on fresh.

### Chaining NetworkManager's dnsmasq in front of dnscrypt-proxy

The instinct is apps → dnsmasq (cache) → dnscrypt-proxy (encrypt) → upstream, reusing
Option A's cache in front of Option B's encryption. **On a NetworkManager-managed machine it
breaks:** NetworkManager's `dns=dnsmasq` plugin tags the upstream it pushes to dnsmasq with the
physical interface (`using nameserver 127.0.2.1#53(via <iface>)` in the logs) — correct for a
real remote resolver, but loopback traffic routed "via" a physical interface gets silently
dropped, so dnsmasq hangs on every query while `dig @127.0.2.1` directly still works.
**Impact:** total DNS outage, harder to spot than the systemd-resolved case because both
processes look healthy (`ps`, `ss` show them listening fine) — only actual queries hang. Since
`dnscrypt-proxy` already caches internally (repeat lookups under 1 ms), there's no caching
benefit lost by leaving dnsmasq out — Option B alone covers both goals.

This "why not" is specific to NetworkManager's `dns=dnsmasq` plugin. Encrypting DNS for a whole
LAN behind a **standalone dnsmasq** (a router/DHCP server) is a different scenario, and chaining
works fine there — see §1.
