# Diagnosing AI-Workload Latency: Local vs. ISP vs. Remote Service

This is the technique that actually found the real root cause in the 2026-09-05 incident,
after synthetic tests (plain `curl` timing loops) looked basically fine. The key idea:

> **Read your *real*, already-open connections with `ss -tin` instead of only running
> synthetic one-shot tests.** The kernel is already measuring RTT, RTT jitter, congestion
> window, and retransmitted bytes for every live TCP connection — including your actual
> Claude Code / AI-API session — for free, in real time.

Synthetic `curl` loops are still useful as a first pass (see `01_QUICK_CHECKLIST.md` step 5)
but they can miss an intermittent problem simply by not happening to run during the bad
window, or by being too short-lived to trigger the same congestion-control behavior a
long-lived session sees.

## 1. Find the real connections

```bash
getent hosts <api-hostname>              # what IP(s) does your client actually talk to?
ss -tin dst <that-ip>                    # or: ss -tin state established '( dport = :443 )'
```

`ss -tin` output comes in pairs of lines per connection: a summary line (local/peer
address:port) and a detail line with the kernel's live stats. Key fields on the detail line:

| Field | Meaning | What to look for |
|---|---|---|
| `rtt:X/Y` | Smoothed RTT / RTT mean deviation (jitter), ms | Y (jitter) much bigger than X, or X suddenly 5-10x higher than other connections to the *same* host at the *same* time |
| `cwnd:` | Current congestion window (packets) | Repeatedly collapsing to a small number (1-4) means the kernel keeps hitting loss and backing off |
| `ssthresh:` | Slow-start threshold after the last loss event | Low and not recovering = repeated loss, not a one-off |
| `bytes_retrans:` | Total bytes retransmitted on this connection so far | Growing steadily over your observation window (not just a one-time ramp-up number) = ongoing loss, not historical |
| `retrans:a/b` | Currently in-flight retransmits / total retransmit events | Non-zero `a` right now = active retransmission happening as you look |

## 2. Take a time series, not a single snapshot

A single `ss -tin` snapshot can't tell you if a bad-looking connection is *currently*
degraded or just carries scar tissue from an earlier, resolved event. Sample repeatedly:

```bash
for i in $(seq 1 10); do
  date +%T
  ss -Htin dst <api-ip> 2>/dev/null | paste -d'|' - - | while IFS='|' read -r head detail; do
    port=$(echo "$head" | grep -oP ':\K[0-9]+(?=\s*$)')
    rtt=$(echo "$detail" | grep -oP 'rtt:\K[0-9.]+/[0-9.]+')
    retrans=$(echo "$detail" | grep -oP 'bytes_retrans:\K[0-9]+')
    echo "  port=$port rtt=${rtt:-?} bytes_retrans=${retrans:-0}"
  done
  sleep 15
done
```

**Note the `-H` flag on `ss`** — it suppresses the header line. Without it, a naive
`paste -d'|' - -` pairing shifts by one line and silently produces garbage (every field
misaligned). This is an easy, non-obvious mistake — verify your parsed output against a raw
`ss -tin` dump before trusting a script's summary.

Read the series for:
- **Connections that stay clean the whole time** → baseline "this destination/path is fine."
- **Connections that develop growing `bytes_retrans` and collapsing `cwnd` mid-series, while
  others to the exact same destination at the exact same time stay clean** → look local
  first (see below on interpreting this).
- **A sudden, sustained jump in `rtt`/jitter across most or all connections to that
  destination, all at the same moment** → look for a shared-path event (gateway reset, Wi-Fi
  roam, ISP-level change) — check `03_WIRED_AND_GATEWAY.md` / `04_WIFI.md` for the same time
  window.

## 3. Interpreting the pattern — what points where

| Pattern observed | Most likely cause | Where to look next |
|---|---|---|
| All connections to the destination clean, all the time | Path is healthy right now | Nothing — false alarm, or the issue is elsewhere (client app, not network) |
| Some connections to the *same* destination at the *same* time badly degraded, others clean | **NOT simple distance/congestion** (that would hit all flows evenly) — more consistent with per-flow shaping/policing, OR a shared local resource flapping mid-flow for some connections and not others | Check `03_WIRED_AND_GATEWAY.md` step 2 for a periodic local outage lining up in time; only escalate to "ISP shaping" once local causes are ruled out |
| All connections degrade together at a regular, repeating interval | A periodic local or path event (gateway reset, watchdog cycle, DFS Wi-Fi channel switch, VRRP/keepalived health-check cycle) | `03_WIRED_AND_GATEWAY.md` step 2 and 4, or `04_WIFI.md` section 3 |
| Consistent RTT to a nearby edge (a few ms) but growing retransmits over minutes, no periodicity | Real, sustained congestion or an actual ISP/shaping issue — now it's worth testing an alternate egress if you have one (see below) | ISP-side comparison, next section |
| Degradation only during specific hours (not periodic on a short timescale) | Real ISP congestion (peak hours) | Compare against a different time of day; a dual-WAN or mobile-hotspot comparison test can confirm |

The single most useful discriminator: **does the same destination, at the same instant, show
wildly different behavior across simultaneous connections?** If yes, that's a strong signal
against "the ISP is shaping us" (which tends to hit all flows to the same place similarly)
and a strong signal *for* something local and intermittent — a flapping NIC, a watchdog reset
loop, or similar. This exact signature is what led to the real root cause in
`06_CASE_STUDY_2026-09-05.md`: what looked like "per-flow ISP shaping" from the client's
point of view was actually a shared gateway that dropped out completely every ~35 seconds,
and different TCP flows just happened to have in-flight data at different points in that
cycle.

## 4. Ruling the ISP in or out, if you have a second egress

If you have a second WAN, VPN, or mobile hotspot available:

```bash
# repeat the exact same ss -tin time series and/or ping -D test through the alternate egress
```

If the pattern disappears on the alternate egress and local checks (`03_`/`04_`) came back
clean, the ISP (or something specific to that WAN path) is implicated. **Do not flip a
shared router's default route to test this without a rollback plan** — a mistimed WAN switch
can itself cause exactly the kind of disruption you're trying to diagnose, and will
contaminate your data if it lands mid-measurement. Use a dead-man-switch/auto-rollback
pattern (a timer that reverts automatically) if this needs to happen on infrastructure other
people depend on, and warn anyone else on that LAN first.

## 5. Why "the AI feels slow" often isn't the model

TCP's own resilience is a double-edged sword here: retransmission and congestion-window
backoff mean a degraded path usually shows up as **added latency and jitter, not hard
errors**. A client library that retries transparently (as most AI/agent tooling does) will
often absorb a bad network period as "that response took an unusually long time" rather than
a visible failure — which is exactly why this class of problem gets misattributed to "the
model is slow" or "the API is having issues" instead of the actual local network cause. If
you check `ss -tin` on the live connection during a slow moment and see retransmits/cwnd
collapse, that's your answer — no need to guess.
