from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from ids.config import ConfigError, TrackerConfig
from ids.flows.tracker import FlowTracker, SummaryCapacityError
from tests.lab02.test_flow_statistics import observation
from tests.lab02.test_flow_tracker import prepared


BASE = datetime(2026, 10, 9, tzinfo=timezone.utc)


def event(seconds=0, protocol="UDP", port=51000):
    return observation(prepared(protocol=protocol, sport=port), timestamp=(BASE + timedelta(seconds=seconds)).isoformat())


def snapshot(tracker):
    return deepcopy((tracker.export_flows(), tracker._tcp_handshakes, tracker._tcp_closes,
                     tracker._generations, tracker._completed_meta, tracker._watermark, tracker._last_sweep))


@pytest.mark.parametrize("protocol, timeout", [("TCP", 3), ("UDP", 2)])
@pytest.mark.parametrize("delta, expected", [(-0.000001, 0), (0, 1), (0.000001, 1)])
def test_expiry_before_at_after_protocol_threshold(protocol, timeout, delta, expected):
    tracker = FlowTracker(TrackerConfig(tcp_idle_timeout=3, udp_idle_timeout=2))
    first = tracker.track(event(protocol=protocol))
    assert tracker.expire(BASE + timedelta(seconds=timeout + delta)) == expected
    assert tracker.active_count == 1 - expected
    if expected:
        summary = tracker.pending_summary()
        assert summary["flow_id"] == first.flow.flow_id and summary["end_reason"] == "idle_timeout"
        assert summary["duration"] == 0 and summary["packet_count"] == 1
        assert summary["state"] == ("CLOSED" if protocol == "TCP" else None)
        assert summary["observed_state"] == ("HANDSHAKE" if protocol == "TCP" else None)
        assert not tracker._tcp_handshakes and not tracker._tcp_closes


def test_activity_renews_last_seen_and_tcp_udp_timeouts_are_independent():
    tracker = FlowTracker(TrackerConfig(tcp_idle_timeout=5, udp_idle_timeout=2))
    tracker.track(event(protocol="TCP"))
    tracker.track(event())
    tracker.track(event(1.5))
    assert tracker.expire(BASE + timedelta(seconds=2)) == 0
    assert tracker.expire(BASE + timedelta(seconds=3.5)) == 1
    assert tracker.active_count == 1 and tracker.pending_summary()["protocol"] == "UDP"
    assert tracker.expire(BASE + timedelta(seconds=5)) == 1


def test_same_key_expiry_is_checked_even_when_sweep_interval_is_long():
    tracker = FlowTracker(TrackerConfig(udp_idle_timeout=2, expiry_check_interval=100))
    first = tracker.track(event())
    second = tracker.track(event(2))
    assert first.flow.flow_id != second.flow.flow_id
    assert tracker.active_count == tracker.pending_count == 1
    assert tracker.pending_summary()["packet_count"] == 1
    assert next(iter(tracker.active_flows.values())).packet_count == 1


def test_periodic_sweep_and_forced_expiry_without_packets():
    tracker = FlowTracker(TrackerConfig(udp_idle_timeout=2, expiry_check_interval=5))
    tracker.track(event())
    tracker.track(event(3, protocol="TCP", port=51001))
    assert tracker.active_count == 2
    assert tracker.expire(BASE + timedelta(seconds=3)) == 1


def test_expired_flow_is_reclaimed_before_skip_new_capacity_policy_between_sweeps():
    tracker = FlowTracker(TrackerConfig(max_active_flows=1, udp_idle_timeout=2, expiry_check_interval=100, capacity_policy="skip_new"))
    tracker.track(event())
    assert tracker.track(event(2, port=51001)).flow is not None
    assert tracker.pending_summary()["end_reason"] == "idle_timeout"


@pytest.mark.parametrize("policy", ["skip_new", "evict_oldest"])
def test_capacity_preserves_existing_updates_and_applies_only_to_new_flows(policy):
    tracker = FlowTracker(TrackerConfig(max_active_flows=1, capacity_policy=policy))
    tracker.track(event())
    assert tracker.track(event(1)).flow is not None
    result = tracker.track(event(2, port=51001))
    assert tracker.active_count == 1
    if policy == "skip_new":
        assert result.flow is None and result.errors[-1].code == "tracker_flow_capacity"
        assert tracker.pending_count == 0 and tracker.export_flows()[0]["packet_count"] == 2
    else:
        assert result.flow is not None and tracker.pending_summary()["end_reason"] == "capacity_eviction"
        assert tracker.pending_summary()["packet_count"] == 2


def test_eviction_uses_oldest_last_seen_and_id_for_deterministic_ties():
    tracker = FlowTracker(TrackerConfig(max_active_flows=2))
    one, two = tracker.track(event()), tracker.track(event(port=51001))
    tracker.track(event(1, port=51002))
    assert tracker.pending_summary()["flow_id"] == min(one.flow.flow_id, two.flow.flow_id)
    assert tracker.pending_summary()["end_reason"] == "capacity_eviction"


def test_out_of_order_clock_never_goes_back_and_stale_new_flow_is_rejected():
    tracker = FlowTracker(TrackerConfig(udp_idle_timeout=2))
    tracker.track(event(3))
    tracker.track(event(2))
    assert tracker._watermark == BASE + timedelta(seconds=3)
    assert tracker.export_flows()[0]["last_seen"].endswith("03.000000Z")
    before = snapshot(tracker)
    result = tracker.track(event(0, port=51001))
    assert result.flow is None and result.errors[-1].code == "tracker_late_event"
    assert snapshot(tracker) == before
    assert tracker.expire(BASE) == 0 and tracker._watermark == BASE + timedelta(seconds=3)


@pytest.mark.parametrize("bad", ["skip", "metadata", "status"])
def test_skipped_invalid_events_do_not_advance_clock_or_expire_any_flow(bad):
    tracker = FlowTracker(TrackerConfig(udp_idle_timeout=2))
    tracker.track(event())
    candidate = event(100)
    if bad == "skip":
        candidate.processing_action = "skip_tracking"
    elif bad == "metadata":
        candidate.normalized["transport"]["src_port"] = -1
    else:
        candidate.preprocess_status = "invalid"
    before = snapshot(tracker)
    assert tracker.track(candidate).flow is None and snapshot(tracker) == before


@pytest.mark.parametrize("now", [None, "bad", datetime(2026, 10, 9)])
def test_expire_rejects_invalid_time_without_mutation(now):
    tracker = FlowTracker()
    tracker.track(event())
    before = snapshot(tracker)
    with pytest.raises(ValueError):
        tracker.expire(now)
    assert snapshot(tracker) == before


def test_summary_queue_backpressure_refuses_eviction_without_losing_data():
    tracker = FlowTracker(TrackerConfig(max_active_flows=1, max_pending_summaries=1))
    tracker.track(event())
    tracker.track(event(1, port=51001))
    before = snapshot(tracker)
    result = tracker.track(event(2, port=51002))
    assert result.flow is None and result.errors[-1].code == "tracker_summary_capacity"
    assert snapshot(tracker) == before
    pending = tracker.pending_summary()
    pending["packet_count"] = 999
    assert tracker.pending_summary()["packet_count"] == 1
    tracker.acknowledge_summary(pending["flow_id"])
    assert tracker.track(event(2, port=51002)).flow is not None


def test_expire_full_queue_fails_atomically_and_recovers_after_ack():
    tracker = FlowTracker(TrackerConfig(udp_idle_timeout=2, max_pending_summaries=1))
    tracker.track(event())
    tracker.track(event(port=51001))
    assert tracker.expire(BASE + timedelta(seconds=2)) == 1
    before = snapshot(tracker)
    with pytest.raises(SummaryCapacityError):
        tracker.expire(BASE + timedelta(seconds=2))
    assert snapshot(tracker) == before
    tracker.acknowledge_summary(tracker.pending_summary()["flow_id"])
    assert tracker.expire(BASE + timedelta(seconds=2)) == 1


@pytest.mark.parametrize("terminal", ["closed", "reset"])
def test_terminal_tcp_flow_expires_preserving_terminal_state_and_cleans_context(terminal):
    from tests.lab02.test_tcp_close import close_normally
    from tests.lab02.test_tcp_handshake import packet

    tracker, base = FlowTracker(TrackerConfig(tcp_idle_timeout=2)), prepared()
    if terminal == "closed":
        close_normally(tracker, base)
    else:
        tracker.track(packet(base, ["RST"]))
    assert tracker.expire(BASE + timedelta(seconds=2)) == 1
    assert tracker.pending_summary()["state"] == terminal.upper()
    assert not tracker._tcp_handshakes and not tracker._tcp_closes


@pytest.mark.parametrize("stage", ["update_statistics", "update_handshake", "update_close"])
def test_failed_new_packet_does_not_partially_expire_or_evict(monkeypatch, stage):
    tracker = FlowTracker(TrackerConfig(udp_idle_timeout=2, max_active_flows=1))
    tracker.track(event())
    before = snapshot(tracker)

    def fail(*args, **kwargs):
        raise ValueError("Injected failure")

    with monkeypatch.context() as patch:
        patch.setattr("ids.flows.tracker." + stage, fail)
        assert tracker.track(event(2, protocol="TCP", port=51001)).flow is None
    assert snapshot(tracker) == before
    assert tracker.track(event(2, protocol="TCP", port=51001)).flow is not None


def test_finish_queues_bounded_batches_preserves_observed_state_and_no_duplicate_output():
    tracker = FlowTracker(TrackerConfig(max_pending_summaries=1))
    tracker.track(event(protocol="TCP"))
    tracker.track(event())
    seen = []
    while tracker.active_count:
        assert tracker.finish() == 1
        summary = tracker.pending_summary()
        seen.append(summary)
        assert summary["end_reason"] == "capture_eof" and summary["state"] == summary["observed_state"]
        tracker.acknowledge_summary(summary["flow_id"])
    assert tracker.finish() == 0 and len({flow["flow_id"] for flow in seen}) == 2


def test_summary_ack_requires_fifo_and_does_not_remove_on_bad_id():
    tracker = FlowTracker()
    tracker.track(event())
    tracker.finish()
    before = tracker.pending_summary()
    with pytest.raises(ValueError):
        tracker.acknowledge_summary("wrong")
    assert tracker.pending_summary() == before


@pytest.mark.parametrize("value", [0, True, 1.5])
def test_pending_summary_limit_is_validated(value):
    with pytest.raises(ConfigError, match="max_pending_summaries"):
        TrackerConfig(max_pending_summaries=value)
