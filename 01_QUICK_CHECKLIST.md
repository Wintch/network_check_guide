# Quick Pre-Work Checklist (~2 minutes)

Run this before starting a session where low latency / no interruptions matter (AI-assisted
coding, pairing, anything with a long-lived connection). Every command is safe and
non-destructive — read-only checks, nothing that touches routing or config.

## 1. Confirm which link/gateway you're actually using

```bash
ip route get 8.8.8.8          # shows the gateway + interface actually used
curl -s --max-time 5 https://api.ipify.org; echo   # public IP — confirms which WAN if dual-WAN
```

If this is a dual-WAN setup, know which WAN you're on *before* you start blaming shaping —
the two links can behave very differently (see `06_CASE_STUDY_2026-09-05.md` and
`reference_claro_link_speed_ceiling` / `reference_personal_icmp_throttling_confirmed` in the
memory system for two concrete examples of "one WAN is fine, the other isn't").

## 2. Wired: interface link health (skip if pure Wi-Fi)

```bash
ip -br link show                                  # is it UP, is there a carrier?
cat /sys/class/net/<iface>/speed                   # negotiated speed — a gigabit NIC stuck
                                                    # at 100 is a real, common failure mode
cat /sys/class/net/<iface>/carrier_changes         # >0 recently = the link flapped
ethtool <iface> 2>/dev/null | grep -E "Speed|Duplex|Link detected"
```

If speed is wrong or carrier_changes is climbing, a physical replug often fixes it on the
spot — see `03_WIRED_AND_GATEWAY.md`.

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

## 5. Real traffic to the service you actually care about

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "attempt $i: connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s\n" \
    --max-time 10 https://<the-real-api-host>/
done
```

Consistent, low, boring numbers = good. Occasional multi-second spikes = go to
`05_AI_WORKLOAD_AND_LATENCY.md` and look at `ss -tin` on your *actual* open connections, not
just synthetic curls — synthetic single-shot tests can miss the exact failure mode that a
long-lived session hits.

## When something looks wrong

Don't reset/restart anything blind. Go in order:
1. `03_WIRED_AND_GATEWAY.md` (or `04_WIFI.md`) — is it local?
2. `05_AI_WORKLOAD_AND_LATENCY.md` — is it the ISP, or the remote service, or still local but
   only visible under real traffic?
3. If it's a shared/production router or LAN segment, do **not** make changes without a
   rollback plan — see the "safety" note in `06_CASE_STUDY_2026-09-05.md`.
