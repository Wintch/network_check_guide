# Worked Example: "ISP Throttling" That Was a Local Watchdog Misfiring

An anonymised, generic worked example. Use it as a template for the next time something
looks like ISP shaping or flaky internet, but the cause may be closer to home. All numbers
below are rounded and illustrative (an example, not measurements from your network).

## Starting symptom

An application that keeps many long-lived connections to a remote API stalls
intermittently, and it is unclear how long any given request should take. The obvious
hypothesis: "my ISP is throttling or shaping my traffic".

## Step 1: synthetic tests look fine

`curl -w` timing loops against the real endpoint (10 attempts, per-phase timing: DNS,
connect, TLS, TTFB) show boring, low, consistent numbers (tens of ms).

A naive conclusion here is "the network is fine, it must be something else". That is
**wrong**: the problem is intermittent and short single-shot tests keep missing it.

## Step 2: read the real, already-open connections

Instead of more synthetic tests, read the live TCP connections that are already open to the
API host:

```bash
ss -tin dst <api-ip>
```

Among 15-20 simultaneous connections to the exact same server, the output shows a split:
some flows are perfectly clean (RTT 3-10 ms, zero retransmits), while others show heavy
retransmission (tens of KB), collapsed congestion windows (cwnd down to 1-4) and RTT spikes
to 30-60 ms with large jitter, all at the same moment.

Sample the same command every 15 seconds for a few minutes. In this example some flows keep
accumulating retransmitted bytes for the whole window, and RTT on specific flows jumps from
about 4 ms to about 35 ms and stays there for over a minute before partially recovering.

**Interpretation at this point:** same server, same instant, very different per-flow
behaviour. That is inconsistent with plain distance or congestion (which hits all flows
evenly). It suggests either per-flow shaping, or a shared local resource that periodically
dies. See `05_AI_WORKLOAD_AND_LATENCY.md` for the full technique.

## Step 3: measure the first hop at 1-second resolution

Ping the LAN gateway directly, with timestamps, once per second:

```bash
ping -D -i 1 -c 140 <your-gateway>
```

In this example the output shows roughly 8-9 seconds of 100% loss, repeating every 35
seconds or so, already at the **first hop**, before any traffic reaches the ISP. That alone
rules out the ISP as the cause.

This reframes step 2: the "per-flow shaping" pattern is consistent with a *periodic full
local outage*. Different TCP flows simply have data in flight at different points of the
cycle, so the damage looks per-flow from the outside.

Confirm the scope by running the same ping from a second, unrelated machine on the same LAN
segment. If it sees the same gaps at the same period, the problem is the segment, not the
host.

## Step 4: find the mechanism

1. **Go to the physical/bridge layer** on the host that serves the segment. In this example
   `dmesg` shows a USB Ethernet adapter (serving the shared bridge) unregistering and
   re-registering on almost exactly the same ~35-second period.
2. **Find what is resetting it.** `systemctl list-timers` shows an active **watchdog
   timer**, running every 30 seconds, whose job is: ping a fixed peer, and if that fails,
   reset the NIC (for example via USB re-authorization).
3. **Audit the watchdog's own log.** Count successes against failures over its whole
   history. In this example the log holds a few dozen successful recoveries against tens of
   thousands of consecutive failures. Grouping the failures by date shows the watchdog
   worked sporadically at first, then at some point began failing on **every single
   cycle**, for weeks.
4. **Reproduce the watchdog's own check by hand** (the same `ping` from the same source
   address, via `ping -I <source-ip> <peer>`, to the same peer). If it shows 100% loss, matching the log, the check itself is
   broken: it can never succeed, so the watchdog resets a healthy NIC on every cycle. Also
   check `ip neigh` on both ends to rule out basic ARP/MAC resolution problems.
5. **Correlate the date** when the failures began with any change made to the network or
   host that day (a reconfiguration, an interface bounce, a package update). Treat this as
   a strong correlation, not as proof, unless you have a packet capture.

## Step 5: fix it and verify

The watchdog fixed nothing for weeks; it caused an outage every cycle. Once you have
confirmed nobody depends on it (see Safety below), stop and disable it:

```bash
systemctl stop <watchdog>.timer
systemctl disable <watchdog>.timer
```

**Verify, do not assume:**

- Immediately afterwards, `ping -D -i 1 -c 120 <your-gateway>` should show 0% loss and no
  gaps (compare: roughly 20% loss with regular gaps before).
- Several minutes later, run a longer test, for example `ping -D -i 1 -c 480`. Expect
  480/480 received.
- Re-check the same live `ss -tin` connections that looked chaotic in step 2. They should
  now be stable, with low RTT and no retransmits.
- Confirm no further NIC register/unregister events in `dmesg`, and that the watchdog's own
  log has stopped growing.

## Method lessons

1. **Diagnose closest to home first.** "ISP shaping" is the hardest hypothesis to prove or
   disprove without disruptive tests. A 1-second ping to the first hop is non-disruptive,
   always available, and should be step one, not a fallback.
2. **Do not read a per-flow symptom as a per-flow cause.** Different simultaneous flows to
   the same destination can look different when the real cause is a periodic full outage.
   Check the whole link before blaming shaping or per-connection policing.
3. **Compare against an independent observer.** Run the same first-hop ping from a second
   host. When two independent observations point at the same LAN segment, believe the
   segment over any single, more elaborate theory.
4. **Audit a watchdog's success/failure ratio.** "There is a watchdog for this" does not
   mean "the watchdog is working". Count successes and failures over its full history
   before trusting it, and reproduce its check by hand.
5. **Verify the fix as rigorously as the diagnosis.** A 2-minute clean ping after a change
   can be luck. A longer clean run, plus re-checking the exact real-traffic connections
   that showed the original symptom, is what closes the loop.

## Safety

Before disabling anything that sounds load-bearing, such as a watchdog, a NIC reset or a
firewall rule:

- **Find out who depends on it.** It may exist for a real reason, such as a genuine
  hardware quirk in the adapter it manages. Even if it is doing net harm now, check with
  whoever owns the machine.
- **Never disable a production watchdog silently.** Tell the owner what you found and what
  you plan to change.
- **Have a rollback.** Prefer `systemctl stop` plus `disable` over deleting the unit, note
  the exact commands to re-enable it (`systemctl enable --now <watchdog>.timer`), and keep a
  copy of any file you change.
- **Change one thing at a time**, and verify (as in step 5) before moving on.

See `03_WIRED_AND_GATEWAY.md` and `05_AI_WORKLOAD_AND_LATENCY.md` for the general
techniques used here, written up as reusable checklists.
