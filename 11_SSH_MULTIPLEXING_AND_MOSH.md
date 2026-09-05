# SSH Multiplexing (ControlMaster) and Mosh — Two Different Fixes for Two Different Callers

Found and set up live on 2026-09-05 while working a long session against a VR lab machine
(`iashur`, reached by mDNS hostname over the LAN) — both came up in the same conversation about
"how do we make this connection more solid," and the right answer turned out to be **two
different tools for two different callers**, not one tool for everybody.

## The two use patterns

- **A scripted caller running many one-shot commands** (`ssh host "cmd"`, back to back, no human
  typing) — this session's own pattern: dozens of short commands (`ps`, `tail`, `cat`, a `ninja`
  build) issued sequentially over a couple of hours. Each one pays a full TCP+SSH handshake
  (auth, key exchange) even though the previous command just proved the connection works.
- **A human typing interactively in a real terminal** — keystrokes want to feel instant, and the
  session needs to survive real-world interruptions (WiFi handoff, laptop sleep, an IP that
  changes) without the whole shell freezing.

These have different bottlenecks, so they get different fixes.

## Fix 1: SSH ControlMaster/ControlPersist (for the scripted caller)

Reuses one already-authenticated connection across every subsequent `ssh host "cmd"` call
instead of a fresh handshake each time. Add to `~/.ssh/config`:

```
Host iashur
    HostName iashur.local
    ...
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 4h
    ServerAliveInterval 5
    ServerAliveCountMax 3
```

(`mkdir -p ~/.ssh/sockets && chmod 700 ~/.ssh/sockets` first — the directory needs to exist.)

**Measured live, same session**: first call `139ms` (real handshake, also creates the master),
every call after that `8ms` (socket reuse) — **~17x faster** for the repeat case. `ssh -O check
host` confirms the master is alive (`Master running (pid=...)`) any time.

`ServerAliveInterval`/`ServerAliveCountMax` matter as much as the speedup: without them, a master
whose connection actually died (not just idle) can sit there looking "alive" while every new
command routed through it hangs — this pair makes the persistent master itself notice a dead
connection (3 missed keepalives at 5s = 15s) and drop it, instead of hanging silently. A same-day
incident (one `ssh` call hanging 120+ seconds) was diagnosed as **host-side CPU contention during
active VR rendering, not a network fault** (see `06_CASE_STUDY_2026-09-05.md` for the general
"diagnose closest to home first" method) — ControlMaster wasn't configured at all when that
happened, so it's ruled out as that day's cause, but the keepalive pair is cheap insurance against
the next flavor of hang regardless of cause.

**Not useful for**: a human typing interactively — the win here is skipping a handshake between
*separate* command invocations; it does nothing for how responsive a single already-open
interactive shell feels while someone types in it.

## Fix 2: Mosh (mobile shell) (for the interactive human)

`mosh host` (works with an existing `~/.ssh/config` alias, same as plain `ssh`) drops you into a
real interactive shell with three properties, all relevant here:

1. **Local echo prediction** — keystrokes appear instantly, predicted client-side, instead of
   waiting on a full round trip to the remote host and back. This is the headline feature and the
   whole reason it "feels" faster than plain SSH over anything but a perfect LAN link.
2. **Robust to network changes** — survives a changed IP, WiFi roaming, sleep/wake, a dropped
   packet — the session picks back up instead of freezing/needing a reconnect. Directly relevant
   here since this LAN machine's DHCP lease has changed before (`.173 -> .174`, see the VR project's
   own notes) — an interactive mosh session wouldn't even notice.
3. **Still secure** — bootstraps via a real SSH connection for authentication and key exchange,
   then hands off to its own encrypted UDP session-sync protocol (SSP) for the actual session.

**Install** (Debian): `apt install mosh` on both ends (client + server in the same package).
Needs a UDP port reachable for the session (default range 60000-61000, one port per session) —
a non-issue on a home LAN with no NAT/firewall in the way.

**Real limitations**: no `-L`/`-R` port forwarding, no agent forwarding, no X11, no file transfer
— it's a terminal-only tool. Keep plain `ssh`/`scp` for anything beyond an interactive shell.

**Not useful for**: a scripted caller issuing one-shot non-interactive commands — mosh has no
clean "run this one command and exit" mode the way `ssh host "cmd"` does; it's built around a
persistent interactive session, so wrapping single automated commands in it would add setup
overhead (an SSH bootstrap + UDP negotiation) per call instead of removing it.

## The rule of thumb

| Caller | Bottleneck | Fix |
|---|---|---|
| Script/agent, many one-shot commands | Repeated handshake latency | SSH `ControlMaster`/`ControlPersist` |
| Human, one interactive session | Round-trip-per-keystroke feel; drops on network change | Mosh |

They're not mutually exclusive — a human's interactive `mosh` session and a script's multiplexed
`ssh` calls can run against the same host at the same time, solving two different problems.
