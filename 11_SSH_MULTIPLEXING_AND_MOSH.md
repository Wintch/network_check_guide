# SSH Multiplexing (ControlMaster) and Mosh — Two Different Fixes for Two Different Callers

"How do I make my connection to a remote host more solid?" has two different answers, because
there are two different kinds of caller: a script and a human. Use **two different tools**, not one
tool for everybody.

## The two use patterns

- **A scripted caller running many one-shot commands** (`ssh host "cmd"`, back to back, no human
  typing) — for example a CI job, a monitoring loop or an automation tool issuing dozens of short
  commands (`ps`, `tail`, `cat`, a build step) one after another. Each one pays a full TCP+SSH
  handshake (auth, key exchange) even though the previous command just proved the connection works.
- **A human typing interactively in a real terminal** — keystrokes want to feel instant, and the
  session needs to survive real-world interruptions (WiFi handoff, laptop sleep, an IP that
  changes) without the whole shell freezing.

These have different bottlenecks, so they get different fixes.

## Fix 1: SSH ControlMaster/ControlPersist (for the scripted caller)

Reuses one already-authenticated connection across every subsequent `ssh host "cmd"` call
instead of a fresh handshake each time. Add to `~/.ssh/config`:

```
Host myserver
    HostName myserver.local
    User youruser
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%C
    ControlPersist 4h
    ServerAliveInterval 5
    ServerAliveCountMax 3
```

Create the socket directory first, because ssh will not create it for you:
`mkdir -p ~/.ssh/sockets && chmod 700 ~/.ssh/sockets`.

Anyone who can read the socket can open sessions as you without authenticating, which is why the
directory is mode 700. Do not place the sockets on a shared or world-writable path.

`%C` is a hash of the connection parameters, which keeps the socket path short. Unix socket paths
are limited to roughly 100 characters, and a long `%r@%h:%p` path can exceed that and fail with
"path too long".

**Typical effect**: the first call pays the real handshake (and creates the master); every call
after that reuses the socket and is typically an order of magnitude faster (for example ~140 ms
versus under 10 ms on a LAN; your numbers will vary). Measure yours with
`time ssh myserver true` run twice. `ssh -O check myserver` confirms the master is alive
(`Master running (pid=...)`) at any time, and `ssh -O exit myserver` closes it.

`ServerAliveInterval`/`ServerAliveCountMax` matter as much as the speedup: without them, a master
whose connection actually died (not just idle) can sit there looking "alive" while every new
command routed through it hangs. This pair makes the persistent master itself notice a dead
connection (3 missed keepalives at 5 s = 15 s) and drop it, instead of hanging silently. Even
without multiplexing, it is cheap insurance against a long hang of unknown cause.

Multiplexing does not cure a slow *host*, though: if a command hangs for a long time, check the
remote host's load (CPU or I/O contention) before blaming the network. The general method is to
diagnose closest to home first.

**Not useful for**: a human typing interactively. The win is skipping a handshake between
*separate* command invocations; it does nothing for how responsive a single already-open
interactive shell feels while someone types in it.

## Fix 2: Mosh (mobile shell) (for the interactive human)

`mosh host` (works with an existing `~/.ssh/config` alias, same as plain `ssh`) drops you into a
real interactive shell with three properties:

1. **Local echo prediction** — keystrokes appear instantly, predicted client-side, instead of
   waiting on a full round trip to the remote host and back. This is the headline feature and the
   reason it "feels" faster than plain SSH over anything but a perfect LAN link.
2. **Robust to network changes** — survives a changed IP, WiFi roaming, sleep/wake, a dropped
   packet; the session picks back up instead of freezing or needing a reconnect. This covers
   changes of the *client's* address (Wi-Fi roaming, a renewed DHCP lease on your laptop). It does
   not cover the *server's* address changing: the client keeps sending to the old IP, so use a
   stable name or a DHCP reservation for the server.
3. **Still secure** — bootstraps via a real SSH connection for authentication and key exchange,
   then hands off to its own encrypted UDP session-sync protocol (SSP) for the actual session.

**Install** (Debian/Ubuntu): `apt install mosh` on both ends (client and server share the same
package). Mosh also needs a UTF-8 locale on both ends. It needs a UDP port reachable for the
session (default range 60000-61000, one port per session), which is a non-issue on a home LAN with
no NAT/firewall in the way. Across a firewall, open that UDP range to the server.

**Real limitations**: no `-L`/`-R` port forwarding, no agent forwarding, no X11, no file transfer
— it's a terminal-only tool. Keep plain `ssh`/`scp` for anything beyond an interactive shell.

**Not useful for**: a scripted caller issuing one-shot non-interactive commands — mosh has no
clean "run this one command and exit" mode the way `ssh host "cmd"` does; it's built around a
persistent interactive session, so wrapping single automated commands in it would add setup
overhead (an SSH bootstrap + UDP negotiation) per call instead of removing it.

## The rule of thumb

| Caller | Bottleneck | Fix |
|---|---|---|
| Script/automation, many one-shot commands | Repeated handshake latency | SSH `ControlMaster`/`ControlPersist` |
| Human, one interactive session | Round-trip-per-keystroke feel; drops on network change | Mosh |

They're not mutually exclusive — a human's interactive `mosh` session and a script's multiplexed
`ssh` calls can run against the same host at the same time, solving two different problems.
