from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

import shipper as sh
import simulate_attacks as sim
from conftest import RULES_SRC, make_env

KEY_SHAPE = re.compile(r"^vsk_")


def test_generation_is_deterministic_and_chronological():
    now = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
    a = sim.build_scenario(seed=7, now=now)
    b = sim.build_scenario(seed=7, now=now)
    c = sim.build_scenario(seed=8, now=now)
    assert [ln.text for ln in a.streams["nginx"]] == [ln.text for ln in b.streams["nginx"]]
    assert [ln.text for ln in a.streams["nginx"]] != [ln.text for ln in c.streams["nginx"]]
    for lines in a.streams.values():
        assert [x.ts for x in lines] == sorted(x.ts for x in lines)
    assert a.total_lines > 300 and a.expected_rules >= {"VSR-1001", "VSR-2001", "VSR-1003"}


def test_only_documentation_and_private_addresses_are_used():
    sc = sim.build_scenario()
    for ip in sc.attacker_ips:
        assert ip.startswith(("203.0.113.", "198.51.100."))  # RFC 5737 TEST-NET
    assert all(ip.startswith("10.20.") for ip in sc.benign_ips)


def test_mixed_traffic_passes_the_local_end_to_end_check():
    verdict = sim.self_check(sim.build_scenario(), str(RULES_SRC))
    assert verdict.ok, (verdict.missing, verdict.unexpected)
    assert verdict.found["VSR-1001"] == 3  # one alert per wave


def test_baseline_alone_raises_no_alerts():
    sc = sim.build_scenario(attacks=(), baseline=True)
    verdict = sim.self_check(sc, str(RULES_SRC))
    assert not verdict.found and verdict.ok


@pytest.mark.parametrize("name", sim.ATTACKS)
def test_each_attack_scenario_triggers_exactly_its_rules(name):
    sc = sim.build_scenario(attacks=(name,), baseline=True)
    verdict = sim.self_check(sc, str(RULES_SRC))
    assert verdict.ok, (name, verdict.missing, verdict.unexpected)
    assert set(verdict.found) == sim.EXPECTED_RULES[name], (name, dict(verdict.found))


def test_input_validation():
    with pytest.raises(ValueError):
        sim.build_scenario(attacks=("nope",))
    with pytest.raises(ValueError):
        sim.build_scenario(minutes=5)


def test_judge_flags_false_positives_and_missing_rules():
    sc = sim.build_scenario(attacks=("ssh_bruteforce",))
    v = sim.judge([{"rule_id": "VSR-2001", "source_ip": "10.20.1.3", "username": None}], sc)
    assert not v.ok and v.missing == {"VSR-1001"} and len(v.unexpected) == 1
    benign_user = sim.judge(
        [{"rule_id": "VSR-1001", "source_ip": "203.0.113.10", "username": "alice"}], sc
    )
    assert benign_user.unexpected  # attacker ip but a benign user is still suspicious


def test_endpoint_and_key_validation(tmp_path):
    assert sim.build_endpoint("https://siem.example.com", allow_insecure_localhost=False).endswith(
        "/api/v1/ingest"
    )
    for bad in (
        "http://siem.example.com",
        "http://127.0.0.1:8000",
        "https://u:p@x.example",
        "https://x.example/p",
    ):
        with pytest.raises(ValueError):
            sim.build_endpoint(bad, allow_insecure_localhost=False)
    sim.build_endpoint("http://127.0.0.1:8000", allow_insecure_localhost=True)
    with pytest.raises(ValueError):
        sim.load_key(None, {})
    with pytest.raises(ValueError):
        sim.load_key(None, {"VIGIL_AGENT_API_KEY": "short"})


def test_cli_modes(tmp_path, capsys, monkeypatch):
    out = tmp_path / "logs"
    assert sim.main(["--output-dir", str(out)]) == 0
    assert {p.name for p in out.iterdir()} == {"auth.log", "access.log", "app.jsonl"}
    assert all(p.stat().st_size > 0 for p in out.iterdir())
    assert sim.main(["--self-check", "--rules-dir", str(RULES_SRC)]) == 0
    assert "RESULT: PASS" in capsys.readouterr().out
    assert sim.main([]) == 2
    assert sim.main(["--output-dir", str(out), "--scenarios", "bogus"]) == 2
    monkeypatch.delenv("VIGIL_AGENT_API_KEY", raising=False)
    assert sim.main(["--server", "https://siem.example.com"]) == 2
    assert sim.main(["--server", "http://siem.example.com"]) == 2


def test_full_pipeline_simulator_to_server_with_verification(env):
    sc = sim.build_scenario()
    totals = sim.send_all(
        env.client,
        "https://testserver/api/v1/ingest",
        env.api_key,
        sim.make_batches(sc, 100),
        delay=0,
        out=lambda _: None,
    )
    assert totals.rejected == 0 and totals.accepted == sc.total_lines and totals.alerts >= 10
    env.login()
    page = env.client.get("/api/v1/alerts", params={"limit": 200}).json()
    verdict = sim.judge(page, sc)
    assert verdict.ok, (verdict.missing, verdict.unexpected)
    assert {
        "VSR-1001",
        "VSR-1002",
        "VSR-1003",
        "VSR-2001",
        "VSR-2002",
        "VSR-2003",
        "VSR-2004",
        "VSR-2005",
        "VSA-0001",
        "VSA-0002",
    } <= set(verdict.found)


def test_verify_path_logs_in_with_credentials(env):
    from conftest import ADMIN_PASSWORD, ADMIN_USER

    sc = sim.build_scenario(attacks=("ssh_bruteforce",))
    sim.send_all(
        env.client,
        "https://testserver/api/v1/ingest",
        env.api_key,
        sim.make_batches(sc, 100),
        delay=0,
        out=lambda _: None,
    )
    env.client.cookies.clear()
    alerts = sim.fetch_alerts(
        env.client,
        "https://testserver",
        ADMIN_USER,
        ADMIN_PASSWORD,
        datetime(2000, 1, 1, tzinfo=UTC),
    )
    assert sim.judge(alerts, sc).ok
    with pytest.raises(RuntimeError):
        sim.fetch_alerts(
            env.client, "https://testserver", ADMIN_USER, "wrong-password", datetime.now(UTC)
        )


def test_send_all_respects_rate_limit_and_surfaces_failures(tight_env):
    env = tight_env
    sc = sim.build_scenario(attacks=("ssh_bruteforce",), baseline=False)
    batches = sim.make_batches(sc, 5)  # many small batches > the 3/min limit
    assert len(batches) > 3
    waits = []

    def sleeper(seconds):
        waits.append(seconds)
        if seconds >= 1:
            env.app.state.ctx.ingest_limiter.reset()  # "time passes": the window empties

    totals = sim.send_all(
        env.client,
        "https://testserver/api/v1/ingest",
        env.api_key,
        batches,
        sleep=sleeper,
        out=lambda _: None,
    )
    assert totals.batches == len(batches) and any(w >= 1 for w in waits)
    with pytest.raises(RuntimeError):
        sim.send_all(
            env.client,
            "https://testserver/api/v1/ingest",
            "vsk_000000000000." + "x" * 30,
            batches[:1],
            out=lambda _: None,
        )


def test_shipper_tails_simulated_logs_into_a_live_server(tmp_path):
    """simulator -> log files -> shipper (real tailing, batching) -> hardened API -> alerts."""
    gen = make_env(tmp_path)
    env = next(gen)
    try:
        logs = tmp_path / "logs"
        assert sim.main(["--output-dir", str(logs)]) == 0
        sc = sim.build_scenario()  # same seed => same expectations as the files on disk
        sender = sh.Sender(
            env.client,
            "https://testserver/api/v1/ingest",
            env.api_key,
            "agent01",
            sleep=lambda _: None,
        )
        specs = [
            sh.SourceSpec("ssh", logs / "auth.log"),
            sh.SourceSpec("nginx", logs / "access.log"),
            sh.SourceSpec("json", logs / "app.jsonl"),
        ]
        shipper = sh.Shipper(
            specs,
            sender,
            sh.StateStore(tmp_path / "state.json"),
            from_beginning=True,
            batch_lines=100,
        )
        shipped = 0
        while read := shipper.step():
            shipped += read
        assert (
            shipped == sc.total_lines and shipper.pending_lines == 0 and sender.dropped_lines == 0
        )
        env.login()
        alerts = env.client.get("/api/v1/alerts", params={"limit": 200}).json()
        verdict = sim.judge(alerts, sc)
        assert verdict.ok, (verdict.missing, verdict.unexpected)
        assert len(verdict.found) == 10
    finally:
        gen.close()
