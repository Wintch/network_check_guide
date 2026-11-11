"""Run the installer against a sandbox: fake root, fake systemctl/dhcpcd/etc. on PATH,
and config paths redirected via env vars, so the real system is never touched."""
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "setup_encrypted_dns.sh"
REAL_PY = shutil.which("python3")

ORIG_TOML = "# shipped\nserver_names = ['old']\n\n[sources]\n"
ORIG_DHCPCD = "hostname\nstatic domain_name_servers=192.168.1.1\n"
ORIG_RESOLV = "nameserver 192.168.1.1\n"


def _fake(bindir, name, body):
    p = bindir / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for n in ("id",):
        _fake(bindir, n, 'echo 0')
    for n in ("chown", "sleep", "apt-get", "dpkg"):
        _fake(bindir, n, "exit 0")
    # dhcpcd -n normally regenerates resolv.conf from dhcpcd.conf; FAKE_DHCPCD_RESOLV simulates
    # what it wrote (printf %b so tests can pass "\n"). It only does so while dhcpcd.conf holds the
    # proxy line, so the rollback's own `dhcpcd -n` does not undo the restore. Unset = leaves the
    # file alone.
    _fake(bindir, "dhcpcd", 'if [ -n "${FAKE_DHCPCD_RESOLV:-}" ] && grep -q "^static domain_name_servers=127.0.2.1" "$DHCPCD_CONF"; then printf "%b" "$FAKE_DHCPCD_RESOLV" > "$RESOLV_CONF"; fi; exit 0')
    _fake(bindir, "dnscrypt-proxy", 'exit "${FAKE_CHECK_RC:-0}"')
    _fake(bindir, "systemctl", 'if [ "$1" = is-enabled ]; then exit "${FAKE_ENABLED_RC:-0}"; fi; exit 0')
    # dnsq.py probes and the final getaddrinfo are faked; the toml editor runs for real.
    _fake(bindir, "python3", f'''
case "$1" in
  */dnsq.py) exit "${{FAKE_PROBE_RC:-0}}" ;;
  -c) exit "${{FAKE_RESOLVE_RC:-0}}" ;;
  *) exec {REAL_PY} "$@" ;;
esac''')
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "dnscrypt-proxy.toml").write_text(ORIG_TOML)
    (etc / "dhcpcd.conf").write_text(ORIG_DHCPCD)
    (etc / "resolv.conf").write_text(ORIG_RESOLV)
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "BK_ROOT": str(tmp_path),
        "TOML": str(etc / "dnscrypt-proxy.toml"),
        "DHCPCD_CONF": str(etc / "dhcpcd.conf"),
        "RESOLV_CONF": str(etc / "resolv.conf"),
    }
    return etc, env


def _run(env, **extra):
    return subprocess.run(["bash", str(SCRIPT)], env={**env, **{k: str(v) for k, v in extra.items()}},
                          capture_output=True, text=True, timeout=60)


def _assert_original(etc):
    assert (etc / "dnscrypt-proxy.toml").read_text() == ORIG_TOML
    assert (etc / "dhcpcd.conf").read_text() == ORIG_DHCPCD
    assert (etc / "resolv.conf").read_text() == ORIG_RESOLV


def test_success_keeps_changes_and_does_not_roll_back(sandbox):
    etc, env = sandbox
    r = _run(env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "static domain_name_servers=127.0.2.1" in (etc / "dhcpcd.conf").read_text()
    assert "lb_strategy = 'p2'" in (etc / "dnscrypt-proxy.toml").read_text()
    assert "restoring" not in r.stdout


def test_check_failure_restores_toml(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_CHECK_RC=1)
    assert r.returncode != 0
    _assert_original(etc)


def test_final_resolution_failure_rolls_back_everything(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_RESOLVE_RC=1)
    assert r.returncode != 0
    _assert_original(etc)


def test_probe_failure_rolls_back(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_PROBE_RC=1)
    assert r.returncode != 0
    _assert_original(etc)


def test_unexpected_is_enabled_status_does_not_abort(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_ENABLED_RC=1)
    assert r.returncode == 0, r.stdout + r.stderr


def _active_lines(path):
    return [l for l in path.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


def test_static_line_inserted_before_first_interface_block(sandbox):
    etc, env = sandbox
    (etc / "dhcpcd.conf").write_text(
        "hostname\n\n# per-interface\ninterface eth0\nstatic ip_address=192.168.1.5/24\n\nprofile home\n"
        "static routers=192.168.1.1\n")
    r = _run(env)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = (etc / "dhcpcd.conf").read_text().splitlines()
    static = [i for i, l in enumerate(lines) if l == "static domain_name_servers=127.0.2.1"]
    assert len(static) == 1
    assert static[0] < lines.index("interface eth0")
    # the interface block is untouched and still follows
    assert "static ip_address=192.168.1.5/24" in lines[static[0]:]
    assert "profile home" in lines


def test_old_top_level_static_removed_but_block_level_one_warned_not_deleted(sandbox):
    etc, env = sandbox
    (etc / "dhcpcd.conf").write_text(
        "static domain_name_servers=192.168.1.1\ninterface eth0\nstatic domain_name_servers=10.0.0.1\n")
    r = _run(env)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (etc / "dhcpcd.conf").read_text()
    assert "192.168.1.1" not in text
    assert text.count("static domain_name_servers=127.0.2.1") == 1
    assert "static domain_name_servers=10.0.0.1" in text.split("interface eth0", 1)[1]
    assert "WARNING" in r.stdout and "inside an interface/profile block" in r.stdout


def test_rerun_is_idempotent(sandbox):
    etc, env = sandbox
    (etc / "dhcpcd.conf").write_text("hostname\ninterface eth0\nstatic ip_address=192.168.1.5/24\n")
    assert _run(env).returncode == 0
    first = (etc / "dhcpcd.conf").read_text()
    assert _run(env).returncode == 0
    assert (etc / "dhcpcd.conf").read_text() == first


def test_no_interface_block_appends_at_end(sandbox):
    etc, env = sandbox
    r = _run(env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert _active_lines(etc / "dhcpcd.conf") == ["hostname", "static domain_name_servers=127.0.2.1"]


def test_leftover_plaintext_nameserver_fails_and_rolls_back(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_DHCPCD_RESOLV="nameserver 127.0.2.1\\nnameserver 192.168.1.1\\n")
    assert r.returncode != 0
    assert "still listed besides 127.0.2.1: 192.168.1.1" in r.stdout
    assert "RDNSS" in r.stdout and "nooption nd_rdnss" in r.stdout
    _assert_original(etc)


def test_leftover_ipv6_nameserver_also_fails(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_DHCPCD_RESOLV="nameserver 127.0.2.1\\nnameserver fe80::1%eth0\\n")
    assert r.returncode != 0
    _assert_original(etc)


def test_only_local_proxy_in_resolv_conf_passes(sandbox):
    etc, env = sandbox
    r = _run(env, FAKE_DHCPCD_RESOLV="# Generated by dhcpcd\\nsearch lan\\nnameserver 127.0.2.1\\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "restoring" not in r.stdout


def test_resolv_conf_without_proxy_is_rewritten_with_only_the_proxy(sandbox):
    etc, env = sandbox
    r = _run(env)  # fake dhcpcd leaves the original 192.168.1.1 resolv.conf in place
    assert r.returncode == 0, r.stdout + r.stderr
    assert _active_lines(etc / "resolv.conf") == ["nameserver 127.0.2.1"]
    assert "dhcpcd did not publish" in r.stdout
