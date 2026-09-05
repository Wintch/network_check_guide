# Gaming Private Networks (GPN) vs. VPN, and Whether a Second WAN Link Helps

"Gaming Private Network" (GPN) is a marketing term some routing services (WTFast, ExitLag,
Mudfish, etc.) use to distinguish themselves from commercial VPNs. It isn't a new technology —
it's SD-WAN-style route optimization (private backbone / better BGP peering to the game's
datacenter), applied narrowly to game traffic instead of your whole connection.

## GPN vs. VPN — what's actually different

| | Commercial VPN | GPN |
|---|---|---|
| **Traffic scope** | Everything: game, browser, Discord, OS updates | Split-tunneling: only the specific game's UDP/TCP flows |
| **How it selects traffic** | Whole-interface tunnel (OpenVPN/WireGuard) | Kernel-level driver (e.g. WFP on Windows) matching ports/destination IPs |
| **Encryption** | Yes, typically AES-256 on every packet | None — encryption is dropped entirely to remove overhead |
| **Effect on ping** | Encrypt/decrypt adds CPU overhead → can raise latency | No crypto overhead; the only latency change comes from the route itself |
| **What it actually changes** | Your public IP + who can see your traffic (privacy) | The network *path* to the specific game server (fewer/better peering hops) |

A GPN is a route optimizer for one flow, not a privacy tool — it doesn't hide or protect
anything, it just tries to hand your game's packets a better path than your ISP's default
routing would pick.

## Does it help if you have two normal WAN links?

Depends on what you're actually trying to fix — route quality or redundancy. These are two
different problems and a GPN only solves one of them.

- **A GPN optimizes whichever single link is currently carrying your traffic.** It doesn't
  combine, load-balance, or fail over between two WAN links by itself — it just improves the
  routing on top of whatever link/interface your OS is already using.
- **If your router already does dual-WAN failover or load-balancing** (pfSense, OPNsense,
  Ubiquiti, MikroTik): a GPN still adds value on top, because it improves the route quality of
  whichever link is active — but it does nothing for the link sitting idle.
- **If what you actually want is resilience** — no visible packet loss or stutter when one ISP
  has a bad moment — that's a different feature: **link bonding / multipath**, not route
  optimization. Look for tools that genuinely use both links at once (packet duplication,
  forward error correction across links, or per-flow steering): e.g. Speedify (consumer
  channel-bonding + FEC), Peplink/enterprise SD-WAN (packet duplication or steering per flow),
  or Mudfish's channel-bonding mode. Most mainstream "GPN" products (ExitLag, WTFast) are
  single-link route optimizers and do **not** do this — check the specific product before
  assuming it aggregates both links.

**Bottom line:** two normal links + a typical GPN = better routing on whichever link is active,
zero automatic redundancy. To actually use both links against packet loss/jitter, you need a
bonding/multipath tool, not a route-optimizer GPN.
