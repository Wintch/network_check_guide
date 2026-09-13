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
> PPPoE), and DNS latency — and presents a colorized verdict with recommendations. Step 6
> (which DNS resolver to use) is a one-time decision, not something to re-check every session.

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

## When something looks wrong

Don't reset/restart anything blind. Go in order:
1. `03_WIRED_AND_GATEWAY.md` (or `04_WIFI.md`) — is it local?
2. `05_AI_WORKLOAD_AND_LATENCY.md` — is it the ISP, or the remote service, or still local but
   only visible under real traffic?
3. If it's a shared/production router or LAN segment, do **not** make changes without a
   rollback plan — see the "safety" note in `06_CASE_STUDY_2026-09-05.md`.
