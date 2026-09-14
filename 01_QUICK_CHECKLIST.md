# Quick Pre-Work Checklist (~2 minutes)

Run this before starting a session where low latency / no interruptions matter (AI-assisted
coding, pairing, anything with a long-lived connection). Every check is safe and
non-destructive — read-only checks, nothing that touches routing or config.

> **Tip — 1-Command Automated Check (Python):**
> Instead of running every command manually, run the provided automated script:
> ```bash
> python3 scripts/quick_check.py
> # or for full 60s gateway sampling:
> python3 scripts/quick_check.py --full
> ```
> It automates steps 1 through 5 below — link health, gateway gaps, Path MTU (1500 vs 1492
> PPPoE), DNS latency, and whether a local DNS cache is active — and presents a colorized
> verdict with recommendations. Steps 6-7 (which resolver to use, setting up a local cache)
> are one-time decisions, not something to re-check every session.

---

## 1. Confirm which link/gateway and IP version you're using

```bash
ip route get 8.8.8.8                                  # IPv4 gateway + interface actually used
ip -6 route get 2001:4860:4860::8888 2>/dev/null      # IPv6 route (if dual-stack is enabled)
curl -s --max-time 5 https://api.ipify.org; echo      # public IPv4
```

If this is a dual-WAN setup, know which WAN you're on *before* you start blaming shaping.
Also check if IPv6 is enabled: a broken IPv6 peering or MTU often introduces a 250-500ms
"Happy Eyeballs" fallback delay on every new connection before dropping back to IPv4.

## 2. Wired: interface link health & MTU (skip if pure Wi-Fi)

```bash
ip -br link show                                  # is it UP, is there a carrier?
cat /sys/class/net/<iface>/speed                   # negotiated speed — a gigabit NIC stuck
                                                    # at 100 is a real, common failure mode
cat /sys/class/net/<iface>/carrier_changes         # >0 recently = the link flapped
ethtool <iface> 2>/dev/null | grep -E "Speed|Duplex|Link detected"
```

**Path MTU & Black Hole Check (PPPoE / VPN):**
```bash
ping -M do -s 1472 -c 2 -W 2 8.8.8.8               # tests 1500 MTU (1472 payload + 28 header)
# If that fails or gives 'Frag needed (mtu=1492)':
ping -M do -s 1464 -c 2 -W 2 8.8.8.8               # tests 1492 MTU (standard PPPoE fiber/DSL)
```
If 1472 fails and 1464 works, your connection is MTU 1492. If large API streams or `git push`
hang while small pings work, check your router's MSS Clamping settings (see `03_WIRED_AND_GATEWAY.md`).

## 3. Wi-Fi: quick signal/quality check (skip if wired)

```bash
iw dev <wlan-iface> link      # signal (dBm), bitrate, tx retries
cat /proc/net/wireless        # link quality / level / noise, all interfaces at a glance
```

Signal weaker than ~-67 dBm, or a bitrate far below your AP's rated speed, means Wi-Fi is
your bottleneck before anything else gets checked. Full detail in `04_WIFI.md`.

## 4. First-hop latency, looking for periodic gaps (not just average latency)

```bash
ping -D -i1 -c 60 <gateway-ip>
```

Don't just read the summary line. A **regular, repeating gap** (e.g. a chunk of missing
sequence numbers every ~30-35 seconds) is a different, worse problem than random small
packet loss — it usually means something local is periodically resetting a link (a flaky
NIC, a misbehaving watchdog, a driver power-save cycle). See `03_WIRED_AND_GATEWAY.md` for
how to spot and confirm this pattern, and `06_CASE_STUDY_2026-09-05.md` for a real one that
took 3 months to notice because nobody looked at the *pattern*, only the average.

## 5. Real traffic to the service you actually care about (including DNS)

```bash
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "attempt $i: dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s\n" \
    --max-time 10 https://<the-real-api-host>/
done
```

- **`time_namelookup` > 0.15s:** DNS lookup is sluggish (local resolver, router or Pi-hole bottleneck).
- **Consistent, low numbers:** healthy connection path.
- **Occasional multi-second spikes:** go to `05_AI_WORKLOAD_AND_LATENCY.md` and look at
  `ss -tin` on your *actual* open connections, not just synthetic curls.

## 6. Which DNS resolver to actually use: speed vs. anonymity

If `time_namelookup` is consistently slow, or you're just deciding what to point the router
at, the resolvers you'd reach for trade off latency against how much they (and anyone
watching the wire) learn about every domain you touch. Roughly fastest-to-most-private:

| Resolver | Typical latency | Privacy trade-off |
|---|---|---|
| **Your ISP's default** | Usually lowest (topologically closest hop) | Worst: plaintext UDP/53 by default, ISP can log/sell/inject and is the easiest party to subpoena |
| **Google `8.8.8.8`** | Very fast, huge anycast footprint | Google ties queries to your IP and retains them briefly as part of the same business that runs ads/analytics |
| **Cloudflare `1.1.1.1`** | Fast — usually the lowest latency in independent benchmarks (DNSPerf) | Published, third-party-audited minimal-logging policy; supports DoH/DoT. Good default for most people |
| **Quad9 `9.9.9.9`** | A few ms slower than Cloudflare in most regions | Swiss nonprofit, blocks known-malicious domains, minimal logging by design — better privacy stance than the big two |
| **Mullvad DoH (`dns.mullvad.net`)** | Similar to Quad9, sometimes a bit slower (fewer PoPs) | No logging, privacy-first jurisdiction; best if you also tunnel through their VPN, since DNS and egress traffic never separate (no DNS-leak risk) |
| **DNS over Tor / random per-query resolver** | Real latency cost — tens to hundreds of ms extra | Only worth it against a well-resourced/state-level adversary; overkill for "keep an AI coding session responsive" |

Practical recommendation for the low-latency use case this guide targets: **Cloudflare
`1.1.1.1`** (plain or DoH) is the best default — it's rarely the slowest option in any
region and doesn't log in a way tied to an ad business. If you'd rather not trust a US-based
company at all, **Quad9 `9.9.9.9`** or **Mullvad's DoH** cost only a handful of extra
milliseconds and are not perceptible in interactive use. Avoid relying on your ISP's default
resolver if you care about privacy at all — it's fast because it's unencrypted and
minimally accountable, not because it's doing anything clever.

Benchmark resolvers against each other from your own network before picking one — don't
trust the table above blindly, PoP placement varies a lot by region:

```bash
for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
  echo -n "$r: "; dig @$r api.anthropic.com +tries=1 +time=2 | grep "Query time"
done
```

Note: even the "fast" public resolvers show real jitter (Google's huge anycast fleet in
particular can sometimes route your query to a farther backend than the ICMP-responding edge
node, so `ping 8.8.8.8` looking fast doesn't guarantee consistent DNS latency). Benchmark with
`dig`, not `ping`.

## 7. Local DNS cache — and whether to encrypt it

**Conclusion first:** most systems have no local caching resolver by default, so every
lookup — even a repeat of the same domain seconds later — pays full round-trip latency to
whichever upstream you picked in step 6. Fix it with one of these two setups, not both:

| Goal | Use | Skip |
|---|---|---|
| Just caching, plaintext is fine | **dnsmasq** via NetworkManager's plugin | systemd-resolved, unbound (see why below) |
| Caching **and** the query itself encrypted (DoT/DoH) | **dnscrypt-proxy → Quad9 DoH** (has its own cache built in) | systemd-resolved (broken on Debian 13, see below); don't also run dnsmasq in front of it (breaks, see below) |

Check what you currently have:

```bash
cat /etc/resolv.conf   # nameserver 127.x.x.x usually means a local cache already exists
ps aux | grep -E "dnsmasq|dnscrypt-proxy|unbound|nscd" | grep -v grep
```

### Option A — caching only: dnsmasq via NetworkManager

Simplest path if you don't need encryption: usually a one-package install
(`dnsmasq-base`), NetworkManager manages the process lifecycle and auto-derives the upstream
server from the connection's own DNS setting, and it survives network switches/VPN.
`systemd-resolved` gives the same caching benefit but pulls in more moving parts if it isn't
already your distro's default (a new package plus re-pointing `/etc/resolv.conf` at its stub);
`unbound` is a full validating recursive resolver, worth it only if you want to stop depending
on any third-party resolver at all — overkill for "just cache what Quad9 already gave me."

```bash
sudo nmcli connection modify "<your connection name>" ipv4.dns "9.9.9.9"   # match NM's record to what you want
sudo mkdir -p /etc/NetworkManager/conf.d
sudo tee /etc/NetworkManager/conf.d/dns-dnsmasq.conf > /dev/null <<'EOF'
[main]
dns=dnsmasq
EOF
sudo systemctl restart NetworkManager   # brief (1-2s) network blip while it reloads
```

Verify: `cat /etc/resolv.conf` → `nameserver 127.0.0.1`. Confirm the cache is live by
resolving the same domain twice — the second call should drop to sub-millisecond:

```bash
dig api.anthropic.com | grep "Query time"   # first: real upstream latency
dig api.anthropic.com | grep "Query time"   # second: ~0 msec, served from local cache
```

Revert: delete `/etc/NetworkManager/conf.d/dns-dnsmasq.conf`, restart NetworkManager.

### Option B — caching + encryption: dnscrypt-proxy → Quad9 DoH

Recommended if you want the query itself unreadable in transit, not just a better resolver
privacy policy. Plain `dig @9.9.9.9` (Option A, or any router/DHCP-provided resolver) is
ordinary UDP/53 — readable by anything on the path, ISP included, regardless of which
resolver you pick. Encryption requires DoT (port 853) or DoH (port 443), which Quad9 supports
but `dnsmasq` cannot speak.

`dnscrypt-proxy` is the tool to reach for over the alternatives: it's in Debian's own repos
(`apt install dnscrypt-proxy`, no third-party repo needed), ships with Quad9 already in its
resolver list, and — unlike `cloudflared` (not packaged for Debian, defaults to Cloudflare's
own resolver, and DNS-proxying is a side feature of a tunneling tool) — it's purpose-built for
"encrypt to the resolver I choose." Debian's package listens on `127.0.2.1:53` by default
(deliberately not `127.0.0.1`, to coexist with another local resolver) via systemd socket
activation.

```bash
sudo apt-get install -y dnscrypt-proxy
sudo sed -i "s/^server_names = .*/server_names = ['quad9-doh-ip4-port443-filter-pri']/" \
  /etc/dnscrypt-proxy/dnscrypt-proxy.toml
sudo systemctl restart dnscrypt-proxy.socket dnscrypt-proxy.service
dig @127.0.2.1 api.anthropic.com   # sanity check before touching system DNS
```

`quad9-doh-ip4-port443-filter-pri` is Quad9's standard filtered/secure resolver (the `9.9.9.9`
one) over DoH — the exact name comes from
`grep -i "^## quad9" -A3 /var/cache/dnscrypt-proxy/public-resolvers.md` (fetched and cached
automatically on first install/start). Verify it actually picked Quad9, not the package's
`cloudflare` default, and that the traffic is genuinely encrypted — check the live connection,
not just the logs:

```bash
journalctl -u dnscrypt-proxy | grep -i quad9        # should show "(DoH) OK" against a quad9-* name
dig @127.0.2.1 <a-fresh-never-queried-domain>
ss -tn | grep -E '9\.9\.9\.9|149\.112\.112\.9'       # should show an ESTAB connection on :443, not :53
```

Point the system at it directly — no dnsmasq in front:

```bash
sudo nmcli connection modify "<your connection name>" ipv4.dns "127.0.2.1"
sudo systemctl restart NetworkManager
cat /etc/resolv.conf   # should show nameserver 127.0.2.1
```

Revert: `sudo nmcli connection modify "<your connection name>" ipv4.dns "9.9.9.9"`, restart
NetworkManager.

### Option B on a `dhcpcd`-managed host (no NetworkManager)

A headless/server-ish Debian box often has no NetworkManager at all — `cat /etc/resolv.conf`
says `# Generated by dhcpcd from <iface>.dhcp` and `nmcli connection show --active` lists only
`lo`. Everything above still applies; only the last step, pointing the system at `127.0.2.1`,
changes. Use dhcpcd's own static override instead of `nmcli`:

```bash
# /etc/dhcpcd.conf, at top level (applies to every interface)
static domain_name_servers=127.0.2.1
```

Apply it with **`sudo dhcpcd -n`** (rebind), not `systemctl restart dhcpcd`: `-n` re-reads the
config without releasing the lease, so it doesn't drop the SSH session you're running it from.

Two things this path gets right that the NetworkManager one doesn't have to think about:

- **It removes the plaintext fallback.** DHCP hands out a list, and a second
  `nameserver 9.9.9.9` line below your local proxy is not a harmless safety net — glibc falls
  back to it whenever the first entry is slow to answer, silently un-encrypting those queries.
  `static domain_name_servers=` replaces the whole list rather than prepending to it. (A
  `/etc/resolv.conf.head` with `nameserver 127.0.2.1` in it looks like the same fix and isn't:
  it prepends, leaving the DHCP entries underneath.)
- **`dnscrypt-proxy -config ... -check` run as root poisons the cache directory.** The Debian
  service runs as `_dnscrypt-proxy`; a root-run `-check` leaves root-owned files in
  `/var/cache/dnscrypt-proxy`, and the service then can't refresh the signed resolver list. It
  keeps working off what's already cached, so this surfaces days later as a stale list. Follow
  any root-run `-check` with
  `chown -R _dnscrypt-proxy:nogroup /var/cache/dnscrypt-proxy /var/log/dnscrypt-proxy`.

`scripts/setup_encrypted_dns.sh` does the whole sequence non-interactively, verifies `127.0.2.1`
answers *before* touching system DNS, and rolls itself back from `/root/dns-rollback-<stamp>/` if
a real lookup fails after the switch.

**What to expect from it, measured (Debian 13, 2026-09-13, gigabit PPPoE link):**

| | before (gateway + 9.9.9.9, plaintext, no local cache) | after (dnscrypt-proxy, Cloudflare + Quad9 DoH, `p2`) |
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

Worth knowing when picking servers: plain-UDP benchmarking is not a good predictor of DoH
latency for the *same* provider. On this host Quad9 measured 34.5 ms over plain UDP but 4 ms on
its DoH endpoint, while Cloudflare went 9.8 ms → 10 ms. Different anycast PoPs answer :53 and
:443. Let `-check`'s own probe, or `journalctl -u dnscrypt-proxy | grep "lowest initial latency"`,
settle it after the switch rather than pre-selecting from a `dig` table.

Verify the traffic really is encrypted by looking at the socket, not the log — resolve a few
never-queried names and catch the connection while it's up (DoH connections close quickly when
idle, so an empty result on a quiet host means nothing):

```bash
ss -tn state established | grep -E '1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112'
```

A row on `:443` is the proof. A row on `:53` — or any outbound `:53` that isn't your local
proxy — is a leak; see [`13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md`](13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md) §3.

### Why not: systemd-resolved with DoT

Tempting because it needs no extra proxy (`DNSOverTLS=yes` plus `DNS=9.9.9.9#dns.quad9.net`
in `/etc/systemd/resolved.conf.d/`), but on Debian 13 (systemd 257) it failed outright: its
D-Bus interface never activated, which silently broke NetworkManager's ability to hand it a
DNS server, leaving it with none configured and `REFUSED` on every query. **Impact:** total
DNS outage, and installing the package also symlinks `/etc/resolv.conf` to its stub, so
disabling the service alone leaves DNS dead until you `apt purge systemd-resolved` and let
NetworkManager rewrite `resolv.conf`. If `systemd-resolved` is *already* your distro's working
default (`resolvectl status` succeeds before you touch anything), adding `DNSOverTLS=yes` is
fine — this failure is specific to bolting it on fresh.

### Why not: chaining dnsmasq in front of dnscrypt-proxy

The instinct is apps → dnsmasq (cache) → dnscrypt-proxy (encrypt) → Quad9, reusing Option A's
cache in front of Option B's encryption. **It breaks:** NetworkManager's `dns=dnsmasq` plugin
tags the upstream it pushes to dnsmasq with the physical interface
(`using nameserver 127.0.2.1#53(via enp5s0)` in the logs) — correct for a real remote
resolver, but loopback traffic routed "via" a physical interface gets silently dropped, so
dnsmasq hangs on every query while `dig @127.0.2.1` directly still works. **Impact:** total
DNS outage again, harder to spot than the systemd-resolved case because both processes look
healthy (`ps`, `ss` show them listening fine) — only actual queries hang. Since
`dnscrypt-proxy` already caches internally (repeat lookups measured at <1ms), there's no
caching benefit lost by leaving dnsmasq out — Option B alone covers both goals.

`scripts/quick_check.py`'s cache detection (section 3 of its report) works with either option
unchanged — it flags any loopback nameserver (`127.x.x.x`), not just `127.0.0.1`.

This "why not" is specific to NetworkManager's `dns=dnsmasq` plugin. If you're encrypting DNS
for a whole LAN behind a **standalone dnsmasq** (a router/DHCP server, not NetworkManager) —
different scenario, different mechanism, chaining works fine there — see
[`13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md`](13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md).

## When something looks wrong

Don't reset/restart anything blind. Go in order:
1. `03_WIRED_AND_GATEWAY.md` (or `04_WIFI.md`) — is it local?
2. `05_AI_WORKLOAD_AND_LATENCY.md` — is it the ISP, or the remote service, or still local but
   only visible under real traffic?
3. If it's a shared/production router or LAN segment, do **not** make changes without a
   rollback plan — see the "safety" note in `06_CASE_STUDY_2026-09-05.md`.
