from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vigilsiem.engine.anomaly import OFF_HOURS_ID, SPIKE_ID, AnomalyConfig, AnomalyScorer
from vigilsiem.models.enums import EventCategory
from vigilsiem.models.schemas import SecurityEvent

BASE = datetime(2026, 11, 2, 9, 0, 0, tzinfo=UTC)


def login(ts, user="alice", ip="198.51.100.7", status="success"):
    return SecurityEvent(
        timestamp=ts,
        source_ip=ip,
        username=user,
        event_category=EventCategory.AUTHENTICATION,
        action="ssh_login",
        status=status,
        raw_log="x",
    )


def web(ts, ip="198.51.100.9"):
    return SecurityEvent(
        timestamp=ts,
        source_ip=ip,
        event_category=EventCategory.WEB,
        action="http_request",
        status="success",
        raw_log="x",
    )


def learn_business_hours(scorer, days=10, user="alice"):
    for d in range(days):
        for hour in (9, 10, 11):
            assert scorer.score(login(BASE + timedelta(days=d, hours=hour - 9))) == []


def test_off_hours_login_flagged_after_baseline():
    s = AnomalyScorer()
    learn_business_hours(s)  # 30 logins at 09-11 UTC
    dets = s.score(login(BASE + timedelta(days=11, hours=15)))  # 03:00 UTC
    assert [d.rule_id for d in dets] == [OFF_HOURS_ID]
    d = dets[0]
    assert d.kind == "anomaly" and d.username == "alice" and d.mitre_technique_id == "T1078"
    assert d.mitre_tactic == "Initial Access"


def test_normal_hour_and_adjacent_hour_not_flagged():
    s = AnomalyScorer()
    learn_business_hours(s)
    assert s.score(login(BASE + timedelta(days=11))) == []  # 09:00
    assert s.score(login(BASE + timedelta(days=11, hours=3))) == []  # 12:00, neighbours 11:00


def test_no_flag_before_enough_samples_and_failed_logins_ignored():
    s = AnomalyScorer()
    for i in range(5):
        s.score(login(BASE + timedelta(days=i)))
    assert s.score(login(BASE + timedelta(days=6, hours=15))) == []  # only 5 samples
    s2 = AnomalyScorer()
    learn_business_hours(s2)
    assert s2.score(login(BASE + timedelta(days=11, hours=15), status="failure")) == []


def test_off_hours_flag_is_rate_limited_per_user():
    s = AnomalyScorer()
    learn_business_hours(s)
    t = BASE + timedelta(days=11, hours=15)
    assert len(s.score(login(t))) == 1
    assert s.score(login(t + timedelta(minutes=5))) == []


def test_users_have_independent_baselines():
    s = AnomalyScorer()
    learn_business_hours(s, user="alice")
    assert s.score(login(BASE + timedelta(days=11, hours=15), user="newbie")) == []


def feed(scorer, minute_counts, ip="198.51.100.9"):
    found = []
    for minute, n in enumerate(minute_counts):
        for k in range(n):
            found.extend(scorer.score(web(BASE + timedelta(minutes=minute, seconds=k % 60), ip=ip)))
    return found


def test_volume_spike_over_3x_rolling_average():
    s = AnomalyScorer()
    dets = feed(s, [5] * 10 + [40])
    spikes = [d for d in dets if d.rule_id == SPIKE_ID]
    assert len(spikes) == 1  # once per minute bucket
    assert spikes[0].source_ip == "198.51.100.9" and "5.0" in spikes[0].summary


def test_steady_or_modest_traffic_not_flagged():
    s = AnomalyScorer()
    assert feed(s, [10] * 15) == []
    s2 = AnomalyScorer()
    assert feed(s2, [10] * 10 + [25]) == []  # 2.5x < 3x


def test_spike_requires_history_and_minimum_volume():
    assert feed(AnomalyScorer(), [100]) == []  # no history yet
    assert feed(AnomalyScorer(), [1] * 10 + [8]) == []  # 8x but below spike_min_events


def test_volume_baseline_is_per_ip():
    s = AnomalyScorer()
    feed(s, [5] * 10, ip="10.0.0.1")
    assert feed(s, [0] * 10 + [40], ip="10.0.0.2") == []  # no history for the new IP


def test_scorer_memory_bounded():
    s = AnomalyScorer(AnomalyConfig(max_subjects=100))
    for i in range(1000):
        s.score(login(BASE, user=f"u{i}", ip=f"10.2.{i // 250}.{i % 250}"))
    assert len(s._logins) <= 100 and len(s._volume) <= 100
