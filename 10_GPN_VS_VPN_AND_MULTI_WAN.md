# Gaming Private Networks (GPN) vs. VPN, and Whether a Second WAN Link Helps

This note explains what these tools do, when they can help, and how to find out whether
they help *you* before paying for or building anything. It is a neutral explainer, not a
product recommendation.

## What each one is

- **VPN (WireGuard, OpenVPN, ...)** — an encrypted tunnel for all (or selected) traffic.
  It changes your public IP and who can see your traffic. Encryption adds a little CPU
  overhead, and the route through the VPN server is usually *longer*, so it rarely lowers
  latency; it does help for privacy, reaching a home network remotely (see
  `07_GAME_AND_VR_STREAMING.md`), or sidestepping a bad ISP peering path by accident.
- **"Gaming Private Network" (GPN)** — a marketing term for commercial services that
  route only a game's traffic (split tunnel, often via a kernel driver matching ports or
  destination IPs) over a provider's own backbone to the game's datacenter. It is
  route optimization, not a new technology, and typically not an encryption/privacy tool.
- **Multi-WAN** — two or more internet uplinks on one router, used for *failover* (switch
  when one dies), *load balancing* (spread separate flows across links), or *bonding /
  multipath* (use both links for the same flow, optionally with packet duplication or
  forward error correction).

| | VPN | GPN-style route optimizer | Multi-WAN |
|---|---|---|---|
| Fixes | Privacy, remote access | A bad path to one server | Outages, capacity |
| Does not fix | Bad Wi-Fi, bufferbloat | Wi-Fi, bufferbloat, local loss | The quality of a single bad route |
| Latency effect | Usually higher | Lower only if your default route is poor | None per flow (unless bonded) |

None of these fixes a problem inside your own network. If lag appears under load, or only
on Wi-Fi, work through `04_WIFI.md` and `08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md` first.

## When route optimization can help

Only when the problem is *beyond your router*: a congested or roundabout path between your
ISP and the destination. Signs: ping is fine to nearby hosts, but high or jittery toward one
specific server, and the extra latency or loss appears at a hop outside your ISP's edge.

## How to measure before you commit

1. **Rule out your own network first**: test wired, and check bufferbloat under load
   (`08_QOS_TRAFFIC_SHAPING_AND_5GHZ.md` section 1).
2. **Trace the path** to the actual server: `mtr -rwzc 100 <server-ip>` (or `tracert`).
   Loss or a latency jump that *continues* to the destination from a given hop is real; a
   single hop with loss that clears afterward is usually just ICMP rate limiting.
3. **Compare over time**, at the hour the problem occurs: baseline run, then the same test
   through the service's free trial or a VPN. Keep each result (loss %, average, worst, jitter)
   and compare like with like.
4. If an alternative path does not clearly beat the default across several runs, it is not
   the bottleneck.

## Does a second WAN link help?

Depends on whether you want better routing or redundancy; they are different problems.

- **Route optimization works on whichever single link carries the traffic.** It does not
  combine or fail over between links by itself.
- **Failover/load-balancing routers** switch a link when it fails and may spread different
  flows over both. A flow does not become faster, and when a link dies, long-lived UDP flows
  (a game session) usually break anyway because the public source IP changes; they just
  reconnect quickly.
- **If you want no visible stutter when one link has a bad moment,** you need bonding or
  multipath with duplication/FEC, which is a different feature from route optimization
  and generally needs an endpoint on the far side (a relay you or a provider run). Check
  that a given product really does this before assuming it aggregates both links.
- A second link also does not help a single cloud-gaming or streaming session's bandwidth
  unless that session is actually spread across links.

**Bottom line:** a route optimizer improves the path on the link in use and gives no
redundancy; multi-WAN gives redundancy and capacity but no better path. Measure first, and
fix local problems (Wi-Fi, bufferbloat) before either.
