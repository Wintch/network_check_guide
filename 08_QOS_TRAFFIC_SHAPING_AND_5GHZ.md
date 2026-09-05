# QoS, Traffic Shaping, and 5GHz Tuning for Real-Time Traffic

How to stop a bulk download/backup/other household device from wrecking latency on a
real-time stream (Parsec, Moonlight/Sunshine, VR, video calls) sharing the same link — and
how to get 5GHz Wi-Fi actually configured for low latency instead of just "on."

## 1. Bufferbloat — the thing that makes this necessary

**Bufferbloat** is excess buffering in a router/modem queue: when the link saturates,
packets sit in an oversized queue instead of being dropped promptly, so ping/latency balloons
(often 10x, into hundreds of ms or seconds) *even though raw throughput still looks fine*.
This is exactly the "everything stutters the moment someone starts a big download" symptom.

Test it:
- [Waveform Bufferbloat Test](https://www.waveform.com/tools/bufferbloat) — grades A-F based
  on latency-under-load, easiest option, no install.
- `flent` (its RRUL test loads both directions simultaneously and tracks latency) or `irtt`
  (lightweight continuous round-trip-time sampling during a load test) if you want a CLI/
  scriptable version.

An A/B grade means the traffic-shaping steps below aren't needed. A D/F grade means they will
make a real, noticeable difference.

## 2. Fixing it: `cake` (the shaper to actually use)

`cake` is a shaper + queue manager in one — no separate `htb`/`tbf` needed — with per-host
fairness and, critically, **priority tins** that let real-time traffic (Parsec, Moonlight,
VR) jump ahead of a backup job. It must be attached to whichever interface is the *actual*
bottleneck — normally your router's WAN-facing NIC — and the configured rate must sit **85-95%
of your real measured sync speed, never 100%**: that headroom is what lets `cake` manage the
queue instead of your ISP's own oversized buffer taking over first.

```bash
# On the router/gateway box, egress-shape the WAN interface
tc qdisc add dev eth0 root cake bandwidth 90mbit ethernet diffserv4
```

`diffserv4` is the preset that enables DSCP-aware priority tins (see step 4). If you're not
comfortable running raw `tc` on your router, **OpenWrt's `sqm-scripts` package** (script
`piece_of_cake.qos`, configured under `/etc/config/sqm` or its Luci GUI) wraps this exact
`tc cake` call behind two boxes: enter your measured down/up rate (at ~85-95%), done. This is
the realistic path for most home setups — see the reality check in section 5.

## 3. `fq_codel` vs. `cake` — do you need the extra complexity?

`fq_codel` (the default qdisc on many distros already) does flow-fairness + CoDel-based drop
scheduling with **no explicit traffic-class prioritization** — it's enough if your only goal
is "don't let one bulk flow starve everything else." Reach for `cake` specifically when you
want a *specific* app's traffic (Parsec/Moonlight/VR) to jump the queue ahead of a backup or
download — that requires DSCP-aware prioritization, which plain `fq_codel` doesn't do.

## 4. DSCP marking to prioritize a specific app

Since Moonlight/Sunshine and Parsec both use known, fixed UDP port ranges (see
`07_GAME_AND_VR_STREAMING.md`), mark their packets so `cake`'s priority tin actually picks
them up:

```bash
# Mark Moonlight/Sunshine's media UDP ports CS5 (voice/real-time class)
iptables -t mangle -A POSTROUTING -p udp --dport 47998:48002 -j DSCP --set-dscp-class cs5

# Parsec: mark whatever static "Host Start Port" range you configured in its settings
iptables -t mangle -A POSTROUTING -p udp --dport <your-parsec-port-range> -j DSCP --set-dscp-class cs5
```

With `diffserv4`, `cake`'s Voice tin already recognizes CS5/CS6/CS7/EF/VA marks automatically
— the `iptables` rule above is enough to route that traffic into the highest-priority tin
ahead of bulk traffic, no additional `tc filter` needed unless you want per-flow overrides.

Note: Sunshine already requests OS-level QoS via `ENET_SOCKOPT_QOS` on its own sockets, but
**most consumer routers ignore untrusted DSCP marks from LAN clients** unless the router
itself is configured to trust/re-mark them — which is exactly what the rule above does when
applied on the router/gateway box itself, on the shaped egress interface.

## 5. Home-router reality check

For nearly everyone, **OpenWrt + the SQM Luci GUI is the practical path** — flash a supported
router, enter 85-95% of your measured down/up speed, done, zero `tc` syntax required. Running
your own dedicated Linux box in the path (bridge/router with two NICs, or a pfSense/OPNsense
box — both also support `cake`) is only worth the extra complexity if you need custom DSCP
marking per app or `tc filter` chains beyond what SQM's simple per-interface shaping gives
you — that's realistically a project for someone already comfortable running a Linux router,
since it also makes NAT/firewall your responsibility.

## 6. 5GHz/6GHz tuning checklist (beyond "connect to the 5GHz SSID")

Picking up from `04_WIFI.md` section 3, specifically for real-time streaming/VR:

- **Channel width:** set the widest your AP/adapter both support — 80MHz on 802.11ac, 160MHz
  on Wi-Fi 6/6E. Many APs don't default to max width; check explicitly
  (`iw dev <iface> info | grep width` client-side, or your AP's admin UI).
- **Fixed, non-DFS channel** if your region's channel list allows it — avoids the multi-second
  forced channel switch described in `04_WIFI.md` section 3, which looks exactly like a
  periodic-outage pattern but is externally triggered (radar detection) and not fixable beyond
  avoiding DFS channels entirely.
- **Dedicate a band/SSID** for latency-sensitive traffic when possible — VR headsets and game
  streaming both benefit disproportionately from *not* sharing airtime with everything else in
  the house, even more than plain video calls do.
- **Power management off** on the streaming client (see `04_WIFI.md` section 4) — this applies
  to laptops/PCs acting as a Parsec/Moonlight client just as much as it does to general
  low-latency work.
- **Line-of-sight and proximity to the AP** matter more for VR headsets specifically — their
  antennas are weaker than a laptop's (often half the spectrum capacity), so the same distance
  that's fine for a laptop can already be marginal for a headset.
