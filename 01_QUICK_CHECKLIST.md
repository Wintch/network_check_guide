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

## 7. Local DNS cache: most systems don't have one by default

Without a local caching resolver, **every single lookup** — even repeats of the same domain
seconds apart — pays full round-trip latency to whichever upstream resolver you picked in
step 6. Check whether you have one:

```bash
cat /etc/resolv.conf   # nameserver 127.0.0.1 or 127.0.0.53 usually means a local cache exists
resolvectl status 2>/dev/null || echo "no systemd-resolved"
ps aux | grep -E "dnsmasq|unbound|nscd" | grep -v grep
```

If `nameserver` points straight at a public IP (e.g. `9.9.9.9`), there's no cache — plain
NetworkManager-managed setups (`dns=default`) are like this out of the box.

**Recommended: dnsmasq via NetworkManager's built-in plugin**, not systemd-resolved or
unbound, for most desktop/laptop Linux setups:

| Option | Why (not) |
|---|---|
| **dnsmasq (`dns=dnsmasq` in NetworkManager)** | Usually already available (`dnsmasq-base` package) or a one-package install; NetworkManager spawns/manages it, auto-derives upstream servers from your connection's DNS setting, survives network switches/VPN. Minimal footprint, trivial to revert. |
| systemd-resolved | Fine if your distro already runs it by default (many do — check first: `resolvectl status`). If it isn't installed, adding it means a new package plus re-pointing `/etc/resolv.conf` at its stub — more moving parts for the same caching benefit. |
| unbound | A full validating recursive resolver — worth it if you want to stop depending on a third-party resolver entirely, but overkill if the goal is just "cache what Quad9/Cloudflare already gave me." |

Setup (Debian/Ubuntu with NetworkManager, assuming `dnsmasq-base` is present):

```bash
sudo nmcli connection modify "<your connection name>" ipv4.dns "9.9.9.9"   # make sure NM's own record matches what you actually want
sudo mkdir -p /etc/NetworkManager/conf.d
sudo tee /etc/NetworkManager/conf.d/dns-dnsmasq.conf > /dev/null <<'EOF'
[main]
dns=dnsmasq
EOF
sudo systemctl restart NetworkManager   # brief (1-2s) network blip while it reloads
```

Verify: `cat /etc/resolv.conf` should now show `nameserver 127.0.0.1`. Confirm the cache is
actually working by resolving the same domain twice back to back — the second call should
drop to sub-millisecond:

```bash
dig api.anthropic.com | grep "Query time"   # first: real upstream latency
dig api.anthropic.com | grep "Query time"   # second: ~0 msec, served from local cache
```

To revert: delete `/etc/NetworkManager/conf.d/dns-dnsmasq.conf` and restart NetworkManager.

`scripts/quick_check.py` detects and warns about a missing local cache automatically (see
below).

### Plaintext vs encrypted DNS (DoT/DoH)

Neither the router's DHCP-provided resolver nor a plain `dig @9.9.9.9`/dnsmasq setup is
encrypted by default — both are ordinary UDP/53, readable by anything on the path (your ISP
included). Going "direct to an external resolver" only buys you a better privacy *policy*
(Quad9 doesn't tie queries to your ISP account or sell ad data); it does **not** buy
encryption by itself. For actual encryption you need DoT (port 853) or DoH (port 443), which
Quad9 supports.

**What didn't work: `systemd-resolved` with `DNSOverTLS=yes`.** Tried first since it needs no
extra proxy — config was `DNS=9.9.9.9#dns.quad9.net` in
`/etc/systemd/resolved.conf.d/`. Result on Debian 13 (systemd 257): broken out of the box.
`systemd-resolved`'s D-Bus interface (`org.freedesktop.resolve1`) failed to activate
(`resolvectl status` timed out), which also silently broke NetworkManager's ability to push
the per-link DNS server to it — the resolver ended up with zero configured upstream servers
and `REFUSED` every query. Installing the package also rewrites `/etc/resolv.conf` into a
symlink pointing at its stub; disabling the service alone leaves that symlink dangling and DNS
fully dead until you `apt purge systemd-resolved` and let NetworkManager regenerate
`resolv.conf`. If your distro already runs `systemd-resolved` by default and it *works*
(check with `resolvectl status` before touching anything), just add `DNSOverTLS=yes` there —
this failure mode is specific to bolting it on where it wasn't already running.

**What works: `dnscrypt-proxy` pointed at Quad9's DoH endpoint.** Available directly via
`apt install dnscrypt-proxy` (no third-party repo, unlike `cloudflared` which isn't packaged
for Debian and defaults to Cloudflare's own resolver anyway). Debian's package listens on
`127.0.2.1:53` by default (deliberately not `127.0.0.1`, to avoid clashing with any other
local resolver) via systemd socket activation.

```bash
sudo apt-get install -y dnscrypt-proxy
sudo sed -i "s/^server_names = .*/server_names = ['quad9-doh-ip4-port443-filter-pri']/" \
  /etc/dnscrypt-proxy/dnscrypt-proxy.toml
sudo systemctl restart dnscrypt-proxy.socket dnscrypt-proxy.service
dig @127.0.2.1 api.anthropic.com   # sanity check before touching system DNS
```

`quad9-doh-ip4-port443-filter-pri` is Quad9's standard filtered/secure resolver (the `9.9.9.9`
one) speaking DoH — found via `grep -i "^## quad9" -A3 /var/cache/dnscrypt-proxy/public-resolvers.md`
after first install/start (it fetches and caches that list itself). Confirm it actually picked
Quad9 (not the package's `cloudflare` default) via
`journalctl -u dnscrypt-proxy | grep -i quad9`, and confirm the traffic is genuinely encrypted
by checking the live connection instead of trusting logs alone:

```bash
dig @127.0.2.1 <a-fresh-never-queried-domain>
ss -tn | grep -E '9\.9\.9\.9|149\.112\.112\.9'   # should show an ESTAB connection on :443
```

Then point the system at it — set it as the connection's DNS server directly:

```bash
sudo nmcli connection modify "<your connection name>" ipv4.dns "127.0.2.1"
sudo systemctl restart NetworkManager
cat /etc/resolv.conf   # should show nameserver 127.0.2.1
```

**Don't also chain this through `dnsmasq`.** The instinct is apps → dnsmasq (cache) →
dnscrypt-proxy (encrypt) → Quad9, keeping the dnsmasq caching layer from section 6 in front of
the new encrypted upstream. It doesn't work: NetworkManager's `dns=dnsmasq` plugin pushes
per-connection DNS servers to dnsmasq over D-Bus tagged with the physical interface (you'll
see `using nameserver 127.0.2.1#53(via enp5s0)` in the logs) — correct for a real remote
resolver reached through that link, but loopback traffic routed "via" a physical interface
gets silently dropped, so dnsmasq hangs on every query while `dig @127.0.2.1` directly still
works fine. `dnscrypt-proxy` already caches internally (confirmed: repeat lookups drop to
<1ms), so there's no caching benefit lost by skipping dnsmasq — just point `ipv4.dns` straight
at `127.0.2.1` and leave dnsmasq out of it entirely.

`scripts/quick_check.py`'s cache detection (section 7) works unchanged here — it flags any
loopback nameserver (`127.x.x.x`) as a local cache, not just `127.0.0.1`.

## When something looks wrong

Don't reset/restart anything blind. Go in order:
1. `03_WIRED_AND_GATEWAY.md` (or `04_WIFI.md`) — is it local?
2. `05_AI_WORKLOAD_AND_LATENCY.md` — is it the ISP, or the remote service, or still local but
   only visible under real traffic?
3. If it's a shared/production router or LAN segment, do **not** make changes without a
   rollback plan — see the "safety" note in `06_CASE_STUDY_2026-09-05.md`.
