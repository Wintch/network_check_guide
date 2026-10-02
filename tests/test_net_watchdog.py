import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import net_watchdog as w


def test_sample_ss_pairs_by_indentation(monkeypatch):
    out = (
        "ESTAB 0 0 10.0.0.1:1 1.1.1.1:443\n\t cubic rtt:10/2 cwnd:10\n"
        "ESTAB 0 0 10.0.0.1:2 1.1.1.1:443\n"  # head with no detail line
        "ESTAB 0 0 10.0.0.1:3 2.2.2.2:443\n\t rtt:5/1\n"
    )
    monkeypatch.setattr(w, "sh", lambda cmd: out)
    assert [(c["peer"], c["rtt"]) for c in w.sample_ss()] == [
        ("1.1.1.1:443", 10.0),
        ("2.2.2.2:443", 5.0),
    ]


def test_save_known_nodes_atomic(tmp_path):
    p = str(tmp_path / "nodes.json")
    w.save_known_nodes(p, {"a": 1})
    assert json.loads(Path(p).read_text()) == {"a": 1}
    assert not Path(p + ".tmp").exists()
