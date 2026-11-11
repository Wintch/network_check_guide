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
> It automates steps 1 through 6 below — link health, gateway gaps, Path MTU (1500 vs 1492
> PPPoE), DNS latency, and whether a local DNS cache is active — and presents a colorized
> verdict with recommendations. It separates "could not measure" (e.g. `ping` missing) from
> real packet loss, and times the HTTPS handshake over IPv4 and, separately, IPv6; an unusable
> IPv6 path is reported as a fact, not as a fault. Choosing a resolver and setting up an
> encrypted local cache are one-time decisions (doc 13), not something to re-check every session.

---

## 1. Confirm which link/gateway and IP version you're using

```bash
ip route get 8.8.8.8                                  # IPv4 gateway + interface actually used
ip -6 route get 2001:4860:4860::8888 2>/dev/null      # IPv6 route (if dual-stack is enabled)
curl -s --max-time 5 https://api.ipify.org; echo      # public IPv4
```

If you have more than one uplink (multi-WAN, a failover link), know which one you are on
*before* you start blaming shaping: the links can behave very differently.
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
If 1472 fails and 1464 works, your connection is MTU 1492. (`quick_check.py` does not stop at
those two sizes: if 1472 fails it binary-searches the largest payload that gets through, so a
1496 or 1420 path is reported as such. It assumes the path is monotonic, i.e. anything smaller
than a size that works also works.) If large API streams or `git push`
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
how to spot and confirm this pattern, and `06_CASE_STUDY_PERIODIC_OUTAGE.md` for a worked
example that stayed unnoticed for months because only the average was ever looked at, not
the *pattern*.

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

## 6. DNS: is there a local cache, and are the queries plaintext?

```bash
grep -v '^#' /etc/resolv.conf                          # nameserver 127.x.x.x = a local cache/proxy answers first
for i in 1 2; do dig example.com | grep "Query time"; done   # 2nd run should be ~0 msec if something caches
```

- **Both runs cost the same:** no local cache; every repeat lookup pays the full round trip.
- **Nameservers are your router, your ISP or a public IP (not `127.x.x.x`):** the queries are
  ordinary UDP/53, readable by anything on the path.
- Choosing a resolver, adding a cache, encrypting with DoH and proving there is no plaintext
  leak are one-time **changes**, not part of this read-only check. They live in
  [`13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md`](13_DNS_ENCRYPTION_AND_LEAK_DETECTION.md) (single
  machine: its section 6; whole LAN: section 1).

## When something looks wrong

Don't reset/restart anything blind. Go in order:
1. `03_WIRED_AND_GATEWAY.md` (or `04_WIFI.md`) — is it local?
2. `05_AI_WORKLOAD_AND_LATENCY.md` — is it the ISP, or the remote service, or still local but
   only visible under real traffic?
3. If it's a shared/production router or LAN segment, do **not** make changes without a
   rollback plan — see the "Safety" section of `06_CASE_STUDY_PERIODIC_OUTAGE.md`.
