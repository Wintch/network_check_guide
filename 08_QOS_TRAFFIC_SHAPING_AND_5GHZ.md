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
# On the router/gateway box. WAN_IF is the WAN-facing interface (eth0, or ppp0 on PPPoE).
WAN_IF=eth0

# Upload: egress shaping on the WAN interface (this shapes UPLOAD only)
tc qdisc replace dev $WAN_IF root cake bandwidth 90mbit diffserv4 nat dual-srchost ethernet
```

**This only shapes upload.** A plain `tc` qdisc on an interface controls what leaves that
interface; it cannot slow down packets arriving from the internet. Most "a download wrecks my
stream" bufferbloat comes from the *download* direction, so you also need ingress shaping,
which on Linux is done by redirecting incoming traffic to an IFB (Intermediate Functional
Block) device and shaping it there:

```bash
# Download: redirect WAN ingress to an IFB device and shape it with cake
modprobe ifb
ip link add name ifb4wan type ifb 2>/dev/null
ip link set ifb4wan up
tc qdisc replace dev $WAN_IF handle ffff: ingress
tc filter replace dev $WAN_IF parent ffff: protocol all prio 1 matchall \
   action mirred egress redirect dev ifb4wan
tc qdisc replace dev ifb4wan root cake bandwidth 450mbit besteffort nat dual-dsthost ingress ethernet
```

Notes on those lines:
- Set each `bandwidth` to 85-95% of the *measured* rate for that direction (upload and
  download are different numbers).
- `nat dual-srchost` / `dual-dsthost` gives per-LAN-host fairness (cake looks through NAT to
  see the real host); keep `nat` only when the box doing the shaping is also the NAT gateway.
- `besteffort` on the ingress side is deliberate: DSCP marks on packets that arrived from the
  internet are not trustworthy, so only the upload side uses the priority tins.
- The `ethernet` keyword tells cake the per-packet link overhead. It is right for a plain
  Ethernet hand-off; for DOCSIS, DSL, or PPPoE use the matching keyword (`docsis`,
  `pppoe-ptm`, ...) or an explicit `overhead N`. A slightly wrong overhead is absorbed by the
  85-95% headroom, a badly wrong one is not.
- These commands are not persistent; put them in a boot script or a systemd unit.

`diffserv4` is the preset that enables DSCP-aware priority tins (see step 4). If you're not
comfortable running raw `tc` on your router, **OpenWrt's SQM (`sqm-scripts`, with
`luci-app-sqm`)** does all of the above — including the IFB ingress plumbing — behind a few
boxes: enter your measured download/upload rate (at ~85-95%), choose the `cake` queue
discipline and the `piece_of_cake.qos` or `layer_cake.qos` script (the latter enables the
DSCP-aware tins used in section 4), done. This is the realistic path for most home setups —
see the reality check in section 5.

## 3. `fq_codel` vs. `cake` — do you need the extra complexity?

`fq_codel` (the default qdisc on many distros already) does flow-fairness + CoDel-based drop
scheduling with **no explicit traffic-class prioritization** — it's enough if your only goal
is "don't let one bulk flow starve everything else." Reach for `cake` specifically when you
want a *specific* app's traffic (Parsec/Moonlight/VR) to jump the queue ahead of a backup or
download — that requires DSCP-aware prioritization, which plain `fq_codel` doesn't do.

## 4. DSCP marking to prioritize a specific app

Since Moonlight/Sunshine and Parsec both use known, fixed UDP port ranges (see
`07_GAME_AND_VR_STREAMING.md`), mark their packets so `cake`'s priority tin actually picks
them up. **Direction matters:** the Sunshine ports (47998 video, 47999 control, 48000 audio)
are the *host's* listening ports. The bulk media flows **host to client**, so those packets
carry the port as their **source** port; `--dport` would only match the small client-to-host
packets.

```bash
# On the Sunshine HOST (marks its own outgoing media; matches SOURCE ports)
iptables -t mangle -A OUTPUT -p udp --sport 47998:48000 -j DSCP --set-dscp-class CS5

# Or on the ROUTER/gateway, for traffic it forwards (remote play leaving through the WAN):
iptables -t mangle -A FORWARD -p udp --sport 47998:48000 -j DSCP --set-dscp-class CS5
iptables -t mangle -A FORWARD -p udp --dport 47998:48000 -j DSCP --set-dscp-class CS5

# Parsec: mark whatever static "Host Start Port" range you configured in its settings
# (match the host's side of the flow the same way: --sport on the host, both on a router)
iptables -t mangle -A FORWARD -p udp --sport <your-parsec-port-range> -j DSCP --set-dscp-class CS5
iptables -t mangle -A FORWARD -p udp --dport <your-parsec-port-range> -j DSCP --set-dscp-class CS5
```

Where the rule lives decides whether it does anything. A mark set on the host only helps if
a device downstream (your router's cake, or a WMM-aware Wi-Fi AP) acts on it. A `FORWARD`
rule on the router only sees traffic that crosses the router; **LAN-to-LAN streaming between
two devices on the same switch or AP never touches the router's WAN shaper**, so for that
case the relevant queue is the Wi-Fi AP's (section 6). Marking and WAN shaping matter most
for remote play and for sharing the uplink with bulk traffic.

With `diffserv4`, `cake`'s Voice tin recognizes CS5/CS6/CS7/EF/VA marks automatically — the
rules above are enough to put that traffic ahead of bulk traffic on the shaped egress
interface, no additional `tc filter` needed unless you want per-flow overrides. (Download-side
marks from the internet are ignored by design, see the `besteffort` note in section 2.)

Note: Sunshine already requests OS-level QoS via `ENET_SOCKOPT_QOS` on its own sockets, but
**most consumer routers ignore untrusted DSCP marks from LAN clients** unless the router
itself is configured to trust/re-mark them — which is what the router-side rules above do.

## 5. Home-router reality check

For nearly everyone, **OpenWrt + the SQM Luci GUI is the practical path** — flash a supported
router, enter 85-95% of your measured down/up speed, done, zero `tc` syntax required. Running
your own dedicated Linux box in the path (bridge/router with two NICs; pfSense/OPNsense
shaping is `fq_codel`-based, and `cake` support there depends on the release) is only worth the extra complexity if you need custom DSCP
marking per app or `tc filter` chains beyond what SQM's simple per-interface shaping gives
you — that's realistically a project for someone already comfortable running a Linux router,
since it also makes NAT/firewall your responsibility.

## 6. 5GHz/6GHz tuning checklist (beyond "connect to the 5GHz SSID")

Picking up from `04_WIFI.md` sections 3-4 (general channel, DFS and power-management
background), specifically for real-time streaming/VR. The VR-specific Wi-Fi points are in
`07_GAME_AND_VR_STREAMING.md` section 4.

- **Channel width:** set the widest your AP and adapter both support. Most 802.11ac clients
  top out at 80MHz (160MHz is optional in 11ac and rare in practice); Wi-Fi 6/6E commonly
  reaches 160MHz. Many APs don't default to max width; check explicitly
  (`iw dev <iface> info | grep width` client-side, or your AP's admin UI). Wider channels
  are more exposed to interference, so step back down if retries rise in a crowded area.
- **Fixed, non-DFS channel** if your region's channel list allows it — avoids the multi-second
  forced channel switch described in `04_WIFI.md` section 3, which looks exactly like a
  periodic-outage pattern but is externally triggered (radar detection) and not fixable beyond
  avoiding DFS channels entirely.
- **Dedicate a band/SSID** for latency-sensitive traffic when possible — streaming and VR
  benefit disproportionately from *not* sharing airtime with everything else.
- **Power management off** on the streaming client (see `04_WIFI.md` section 4), including
  laptops/PCs acting as a Parsec/Moonlight client.
- **Proximity to the AP** matters more for VR headsets — their antennas are weaker than a
  laptop's (often 2x2), so a distance that's fine for a laptop can already be marginal.
