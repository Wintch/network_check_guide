"""Run the installer against a sandbox: fake root, fake systemctl/dhcpcd/etc. on PATH,
and config paths redirected via env vars, so the real system is never touched."""
import os
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
    for n in ("dhcpcd", "chown", "sleep", "apt-get", "dpkg"):
        _fake(bindir, n, "exit 0")
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
