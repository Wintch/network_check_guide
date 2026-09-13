# Wired LAN & Gateway Validation

Covers everything between your NIC and your default gateway — the segment that turned out to
be the actual root cause in the 2026-09-05 incident (see `06_CASE_STUDY_2026-09-05.md`), not
the ISP.

## 1. NIC link state and negotiation

```bash
ip -br link show                              # UP/DOWN + carrier at a glance
cat /sys/class/net/<iface>/speed               # negotiated link speed in Mbps
cat /sys/class/net/<iface>/duplex
cat /sys/class/net/<iface>/carrier_changes     # cumulative flap count since boot
ethtool <iface>                                 # full negotiation detail
ethtool -S <iface> | grep -iE "error|drop|discard"   # driver-level error counters
```

**Known real failure mode:** a gigabit-capable NIC silently renegotiating down to 100 Mbps
after a link blip (bad cable, dirty connector, flaky switch port). Symptom: normal-looking
ping to the gateway can still show real loss (20-30%) because the link itself is degraded,
not congested. Fix is almost always a physical replug — confirm with `speed` before and
after. A rising `carrier_changes` count without an obvious cause (nobody touched the cable)
is worth investigating on its own.

## 2. High-resolution ping — look for the *pattern*, not just the average

A plain `ping -c 20` summary line ("0% loss, avg 5ms") can hide a serious periodic problem if
the bad window is short and the sample is short too. Run longer, with timestamps, and look
for gaps:

```bash
ping -D -i1 -c 120 <gateway-ip> > /tmp/ping_check.log
grep -oP '^\[\K[0-9.]+' /tmp/ping_check.log | awk 'NR>1{d=$1-prev; if(d>1.5) print "gap of " d "s"} {prev=$1}'
```

- **No gaps, 0% loss** → this hop is healthy.
- **A one-off gap** → could be a transient blip (Wi-Fi roam, DHCP renewal, a one-time
  reconnect) — not necessarily worth chasing unless it recurs.
- **Regular gaps at a fixed interval** (e.g. every ~30-35 seconds, every time) → **this is a
  structural problem, not noise.** It means something is periodically cycling a link or
  route. Common causes, in order of how often they show up in practice:
  1. A **watchdog/cron script** on a router or bridge host that pings something, decides
     it's down, and resets an interface — see step 4 below. This was the actual cause in
     the case study: a script had been doing this every ~35 seconds for weeks.
  2. A **flaky NIC/driver** (common with certain USB-Ethernet chipsets — see the note on
     `cdc_ncm`/ASIX-family adapters below) that genuinely drops its RX path and
     re-enumerates on its own.
  3. Wi-Fi power-save or roaming cycling — see `04_WIFI.md`.
  4. A DHCP lease renewal or a keepalived/VRRP health-check cycle with a similar period.

Don't stop at "found a periodic gap" — find *which* of these it is before touching anything.
Steps 3 and 4 below are how.

## 3. Confirm scope: is it just this host, or the whole segment?

Run the same high-res ping from a **second, unrelated device on the same LAN segment**
(different NIC, different OS if possible). If the gaps line up in time on both, the problem
is upstream of both hosts — the shared switch, bridge, or gateway — not either host's own NIC
or Wi-Fi. This single comparison is what turns "my machine feels laggy" into "the LAN's
gateway path is broken for everyone," which is a completely different (and usually easier)
problem to fix.

## 4. Find what's touching the interface — dmesg + scheduled jobs

If you have access to the router/bridge host itself (not just a client on the LAN):

```bash
dmesg -T | grep -iE "carrier|link is|reset|unregister|register" | tail -40
# Regular register/unregister or up/down events at the same interval as the ping gaps
# means something is actively cycling this NIC.

systemctl list-timers --all --no-pager     # any timer with a short interval (30s, 1min...)?
crontab -l                                  # for the relevant user
grep -rl "authorized\|unbind\|bind" /etc/systemd/system /usr/local/sbin 2>/dev/null
# ^ common pattern for a USB-NIC reset watchdog: toggling /sys/.../authorized or
#   unbind/bind on a USB driver
```

If you find a timer/service doing this, check its own log before assuming it's doing its job
correctly:

```bash
journalctl -u <service-name> --no-pager -n 50
tail -50 <its log file, if any>
```

**Critical check: does the watchdog's own health check actually succeed after it "fixes"
things, or does it fail every single cycle forever?** A watchdog that resets something every
cycle without ever recovering is not protecting you — it *is* the outage. Count successes vs.
failures in its log before trusting it:

```bash
grep -c "OK" watchdog.log
grep -c "still down\|failed\|CAIDA" watchdog.log
```

If failures vastly outnumber successes over a long period, the watchdog's own check is
broken (wrong source IP, a firewall rule that changed, an ARP/bridge quirk) — the fix is to
either correct the check or disable the watchdog while you investigate, not to leave it
running "just in case." See `06_CASE_STUDY_2026-09-05.md` for exactly this scenario, with
real numbers (61,066 failed cycles vs. 32 successful ones over 3 months).

## 5. Known-flaky hardware pattern: USB-Ethernet adapters

USB-Ethernet dongles (common on machines/VMs that ran out of physical NIC ports) are a
recurring source of exactly this kind of periodic failure. Specifically:

- Chips in the **ASIX AX88179x family**, when they enumerate via the generic `cdc_ncm`
  Linux driver (very common with rebranded/clone adapters — check with `ethtool -i
  <iface>` and `dmesg | grep -i asix`), have a documented failure mode where the **RX path
  hangs while the link light / carrier stays up** — `ip link` still shows UP, `ping` may even
  half-work, but real throughput on receive collapses or dies. A plain `ip link down/up`
  does **not** fix this; only a real USB re-enumeration does (physical replug, or toggling
  `/sys/bus/usb/devices/<dev>/authorized` 0→1, or unbind/bind on the driver).
- If you're chasing exactly this symptom: `ethtool -S <iface>` errors will often look clean
  (0 errors) because the problem is at the USB/driver layer, not the Ethernet PHY — don't
  rule it out just because the error counters are zero.
- Long-term fix for chronic cases: swap the adapter for one using the Realtek `r8152`
  driver, which has been far more stable in practice on this kind of setup.

## 6. Path MTU, PPPoE (1492), and PMTUD Black Holes

A classic failure signature: **`ping` to 8.8.8.8 works fine with 0% loss, but `git push`, large API responses, or SSH file transfers freeze indefinitely.**

Why this happens:
- Standard Ethernet MTU is **1500 bytes**.
- Residential fiber / DSL connections using **PPPoE** encapsulate 8 bytes of PPP headers, leaving an MTU of **1492 bytes**.
- VPNs (WireGuard, IPsec) reduce MTU further (often **1420** or **1392**).
- If your OS tries to send a 1500-byte packet with the DF (Don't Fragment) flag set, intermediate routers must reply with an ICMP Type 3 Code 4 (*"Fragmentation Needed"*).
- If an upstream firewall or ISP router drops these ICMP messages, you hit a **PMTUD Black Hole**: your machine keeps retransmitting the oversized packet, waiting for an ACK that never comes, while small packets (like pings or TCP ACKs) pass effortlessly.

### How to test:
```bash
# Test standard 1500 MTU (1472 payload + 28 bytes IP/ICMP headers = 1500)
ping -M do -s 1472 -c 2 -W 2 8.8.8.8

# If that fails or gives "Frag needed (mtu=1492)", test PPPoE 1492 MTU (1464 payload + 28 = 1492):
ping -M do -s 1464 -c 2 -W 2 8.8.8.8

# If on a VPN / tunnel, test 1420 MTU (1392 payload + 28 = 1420):
ping -M do -s 1392 -c 2 -W 2 8.8.8.8
```

Read the error carefully — it tells you *where* the packet died:
- **`ping: sendmsg: Message too long`** — the kernel refused to send it at all. Your local
  interface already has a smaller MTU configured (normal and expected on a PPPoE/VPN
  interface). This is not a black hole, it's just confirming the local MTU.
- **`Frag needed and DF set` / an explicit ICMP reply** — a router along the path told you
  the real limit. Also not a black hole — PMTUD is working correctly.
- **100% packet loss with no error and no ICMP reply at all** — the oversized packet left
  your machine and nothing came back. *This* is the actual PMTUD black hole signature.

### The fix:
- On your local machine: set MTU explicitly if using PPPoE/VPN:
  `sudo ip link set dev <iface> mtu 1492`
- On the router/firewall: ensure **TCP MSS Clamping** is enabled on the WAN interface. In `nftables`:
  `nft add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu`
  Or in `iptables`:
  `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`

## 7. NIC Hardware Quirks: Energy Efficient Ethernet (EEE) & Offloading

Modern NICs (especially Realtek `r8169`/`r8125` and Intel `e1000e`/`igc`) include power-saving and hardware offloading features that can induce micro-stutters:

1. **EEE (Energy Efficient Ethernet / 802.3az):**
   Puts the PHY into low-power mode during brief link idle periods. Waking up takes microseconds to milliseconds, causing jitter spikes or dropped frames under sudden burst traffic.
   ```bash
   # Check if EEE is active:
   ethtool --show-eee <iface>

   # Disable EEE:
   sudo ethtool --set-eee <iface> eee off
   ```

2. **Hardware Offloading (TSO / GSO / GRO):**
   TCP Segmentation Offload allows the kernel to pass 64KB buffers to the NIC to segment into MTU-sized packets. On buggy drivers or USB dongles, this can cause silent frame drops or stalls.
   ```bash
   # Check active offload features:
   ethtool -k <iface> | grep -E "segmentation|generic-receive"

   # Test disabling TSO and GSO to rule out driver offload bugs:
   sudo ethtool -K <iface> tso off gso off
   ```

## Safety note

Never disable/change a watchdog, reset a NIC, or touch routing on a shared/production router
without: (1) confirming who else depends on that link right now, (2) having a rollback plan
(a dead-man-switch timer that reverts automatically is a good pattern for anything touching a
default route or firewall), and (3) doing it as a deliberate, isolated step — not bundled
silently into a diagnostic session. See `06_CASE_STUDY_2026-09-05.md` for a worked example of
asking for confirmation before disabling a chronic-but-load-bearing-sounding watchdog.
