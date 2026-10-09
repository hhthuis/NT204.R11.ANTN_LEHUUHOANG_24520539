"""Observed packet accounting and time bounds, independent of TCP state."""

import base64
import json
from copy import deepcopy
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from ids.decoders.decoder import decode_event
from ids.flows.models import FlowDirection, FlowProtocol
from ids.flows.statistics import update_statistics
from ids.flows.tracker import FlowTracker, make_flow_id
from ids.models import ApplicationInfo
from ids.preprocessors.preprocessor import preprocess_event
from tests.lab02.test_flow_models import make_flow
from tests.lab02.test_flow_tracker import prepared, reverse


def observation(event, *, length=54, timestamp="2026-10-09T00:00:00Z", flags=None):
    packet = deepcopy(event.packet)
    packet.captured_length = length
    packet.timestamp = timestamp
    if flags is not None:
        packet.transport.fields["flags"] = flags
    return preprocess_event(decode_event(packet))


def test_directional_accounting_uses_captured_bytes_and_counts_first_packet_once():
    tracker = FlowTracker()
    initial = prepared()
    tracker.track(observation(initial, length=60))
    first = tracker.export_flows()[0]
    assert first["packet_count"] == first["forward_packet_count"] == 1
    assert first["byte_count"] == first["forward_byte_count"] == 60
    assert first["backward_packet_count"] == first["backward_byte_count"] == 0
    tracker.track(observation(reverse(initial), length=70, timestamp="2026-10-09T00:00:01Z"))
    tracker.track(observation(initial, length=100, timestamp="2026-10-09T00:00:02Z"))
    flow = tracker.export_flows()[0]
    assert (flow["packet_count"], flow["byte_count"]) == (3, 230)
    assert (flow["forward_packet_count"], flow["forward_byte_count"]) == (2, 160)
    assert (flow["backward_packet_count"], flow["backward_byte_count"]) == (1, 70)
    assert flow["duration"] == 2


def test_bytes_are_captured_length_including_headers_not_wire_or_payload_length():
    event = prepared()
    event.packet.captured_length, event.packet.wire_length = 80, 120
    event.packet.payload.length = 4
    event.packet.payload.base64 = base64.b64encode(b"data").decode()
    event = preprocess_event(decode_event(event.packet))
    tracker = FlowTracker()
    tracker.track(event)
    assert tracker.export_flows()[0]["byte_count"] == 80
    assert event.packet.payload.length == 4 and event.packet.wire_length == 120


@pytest.mark.parametrize("flags, expected", [
    (["SYN"], (1, 0, 0, 0)), (["SYN", "ACK"], (1, 1, 0, 0)),
    (["ACK"], (0, 1, 0, 0)), (["FIN", "ACK"], (0, 1, 1, 0)),
    (["RST", "ACK"], (0, 1, 0, 1)), (["PSH", "ACK"], (0, 1, 0, 0)),
    (["ECE", "CWR", "NS"], (0, 0, 0, 0)), ([], (0, 0, 0, 0)),
])
def test_empty_payload_tcp_packets_count_each_present_flag_without_state_transitions(flags, expected):
    tracker = FlowTracker()
    event = observation(prepared(), flags=flags)
    associated = tracker.track(event)
    flow = tracker.export_flows()[0]
    assert tuple(flow[key] for key in ("syn_count", "ack_count", "fin_count", "rst_count")) == expected
    assert flow["packet_count"] == 1 and flow["byte_count"] == 54
    assert event.packet.payload.length == 0 and associated.flow.state == "NEW"


def test_combined_flags_sum_across_both_directions_without_deduplicating_packets():
    tracker = FlowTracker()
    initial = prepared()
    tracker.track(observation(initial, flags=["SYN"]))
    tracker.track(observation(reverse(initial), flags=["SYN", "ACK"]))
    tracker.track(observation(initial, flags=["ACK"]))
    tracker.track(observation(initial, flags=["FIN", "ACK"]))
    tracker.track(observation(reverse(initial), flags=["RST", "ACK"]))
    flow = tracker.export_flows()[0]
    assert (flow["syn_count"], flow["ack_count"], flow["fin_count"], flow["rst_count"]) == (2, 4, 1, 1)
    assert flow["packet_count"] == 5 and flow["byte_count"] == 270


def test_duplicate_flags_in_one_observation_count_once_but_retransmission_counts_again():
    tracker = FlowTracker()
    event = observation(prepared(), flags=["SYN", "syn"])
    assert event.preprocess_status == "partial" and event.processing_action == "track"
    tracker.track(event)
    tracker.track(event)  # same packet_id/sequence/timestamp, another accepted observation
    flow = tracker.export_flows()[0]
    assert flow["syn_count"] == flow["packet_count"] == 2 and flow["byte_count"] == 108


def test_missing_flags_count_bytes_and_packets_without_inventing_flags():
    event = prepared()
    event.packet.transport.fields = {}
    event = preprocess_event(decode_event(event.packet))
    tracker = FlowTracker()
    tracker.track(event)
    flow = tracker.export_flows()[0]
    assert flow["packet_count"] == 1 and flow["byte_count"] == 54
    assert all(flow[name] == 0 for name in ("syn_count", "ack_count", "fin_count", "rst_count"))
    assert event.reason and event.normalized["transport"]["flags"] == []


def test_udp_has_directional_statistics_but_never_tcp_counters_or_state():
    initial = prepared(protocol="UDP")
    tracker = FlowTracker()
    tracker.track(observation(initial, length=47))
    tracker.track(observation(reverse(initial), length=48))
    tracker.track(observation(initial, length=42))
    flow = tracker.export_flows()[0]
    assert flow["protocol"] == "UDP" and flow["state"] is None
    assert (flow["packet_count"], flow["byte_count"]) == (3, 137)
    assert (flow["forward_packet_count"], flow["forward_byte_count"]) == (2, 89)
    assert (flow["backward_packet_count"], flow["backward_byte_count"]) == (1, 48)
    assert all(flow[name] == 0 for name in ("syn_count", "ack_count", "fin_count", "rst_count"))


def test_out_of_order_times_use_utc_min_max_without_changing_first_observed_orientation():
    tracker = FlowTracker()
    initial = prepared()
    first = tracker.track(observation(initial, timestamp="2026-10-09T00:00:02Z"))
    newer = tracker.track(observation(initial, timestamp="2026-10-09T00:00:04.500000Z"))
    older = tracker.track(observation(reverse(initial), timestamp="2026-10-09T07:00:01+07:00"))
    flow = tracker.export_flows()[0]
    assert flow["start_time"] == "2026-10-09T00:00:01.000000Z"
    assert flow["last_seen"] == "2026-10-09T00:00:04.500000Z" and flow["duration"] == 3.5
    assert flow["endpoint_a"]["ip"] == "10.0.0.2" and older.flow.direction == "backward"
    assert first.flow.flow_id == newer.flow.flow_id == older.flow.flow_id


def test_equal_timestamps_have_zero_duration_while_microseconds_are_preserved():
    tracker = FlowTracker()
    event = observation(prepared(), timestamp="2026-10-09T00:00:00.123456Z")
    tracker.track(event)
    tracker.track(reverse(event))
    flow = tracker.export_flows()[0]
    assert flow["duration"] == 0 and flow["last_seen"] == "2026-10-09T00:00:00.123456Z"
    tracker.track(observation(event, timestamp="2026-10-09T00:00:00.123457Z"))
    assert tracker.export_flows()[0]["duration"] == 0.000001


@pytest.mark.parametrize("protocol", ["HTTP", "DNS", "SMTP", "MIME"])
def test_first_supported_application_upgrades_unknown_without_later_downgrades(protocol):
    tracker = FlowTracker()
    first = prepared()
    tracker.track(first)
    packet = deepcopy(reverse(first).packet)
    kind = "response" if protocol in ("HTTP", "DNS") else "message"
    packet.application = ApplicationInfo(protocol, kind, {"headers": {}, "body_length": 0})
    associated = tracker.track(preprocess_event(decode_event(packet)))
    assert associated.flow.flow_id == tracker.export_flows()[0]["flow_id"]
    assert tracker.export_flows()[0]["application_protocol"] == protocol
    tracker.track(first)
    packet.application = ApplicationInfo("DNS" if protocol != "DNS" else "HTTP", "response", {})
    tracker.track(preprocess_event(decode_event(packet)))
    assert tracker.export_flows()[0]["application_protocol"] == protocol


def test_skipped_and_corrupt_existing_flow_events_leave_all_statistics_unchanged():
    tracker = FlowTracker()
    initial = prepared()
    tracker.track(initial)
    before = tracker.export_flows()
    skipped = observation(initial, timestamp="2026-10-09T00:10:00Z")
    skipped.processing_action = "skip_tracking"
    assert tracker.track(skipped).flow is None and tracker.export_flows() == before
    bad = deepcopy(initial)
    bad.normalized["transport"]["flags"] = ["BOGUS"]
    assert tracker.track(bad).flow is None and tracker.export_flows() == before
    bad = deepcopy(initial)
    bad.normalized["captured_length"] = 999
    assert tracker.track(bad).flow is None and tracker.export_flows() == before
    tracker.track(reverse(initial))
    assert tracker.export_flows()[0]["packet_count"] == 2


def test_concurrent_flows_keep_independent_statistics_and_skip_does_not_create_flow():
    tracker = FlowTracker()
    first, second = prepared(), prepared(sport=51001)
    one = tracker.track(observation(first, length=60))
    two = tracker.track(observation(second, length=70))
    tracker.track(observation(reverse(first), length=80))
    skipped = prepared(sport=51002)
    skipped.processing_action = "skip_tracking"
    tracker.track(skipped)
    flows = {flow["flow_id"]: flow for flow in tracker.export_flows()}
    assert len(flows) == 2
    assert (flows[one.flow.flow_id]["packet_count"], flows[one.flow.flow_id]["byte_count"]) == (2, 140)
    assert (flows[two.flow.flow_id]["packet_count"], flows[two.flow.flow_id]["byte_count"]) == (1, 70)


def test_export_and_removed_flow_snapshots_remain_detached_and_new_lifetime_resets_statistics():
    tracker = FlowTracker()
    event = prepared()
    first = tracker.track(event)
    before = tracker.export_flows()
    view = tracker.active_flows
    tracker.track(reverse(event))
    assert before[0]["packet_count"] == 1 and next(iter(view.values())).packet_count == 1
    assert tracker.export_flows()[0]["packet_count"] == 2
    removed = tracker.remove_flow(next(iter(tracker.active_flows)))
    second = tracker.track(event)
    assert removed.packet_count == 2 and first.flow.flow_id != second.flow.flow_id
    assert tracker.export_flows()[0]["packet_count"] == 1
    assert json.loads(json.dumps(tracker.export_flows()))[0]["byte_count"] == 54


def test_zero_captured_length_is_a_packet_observation_and_never_negative_bytes():
    tracker = FlowTracker()
    tracker.track(observation(prepared(), length=0))
    flow = tracker.export_flows()[0]
    assert flow["packet_count"] == 1 and flow["byte_count"] == 0


def test_statistics_helper_builds_new_record_and_counts_duplicate_flag_once():
    flow = make_flow()
    before = deepcopy(flow.to_dict())
    updated = update_statistics(flow, direction=FlowDirection.BACKWARD,
                                timestamp=datetime(2026, 10, 9, 0, 0, 1, tzinfo=timezone.utc),
                                captured_length=70, flags=("SYN", "ACK", "ACK"))
    assert flow.to_dict() == before
    assert updated.packet_count == updated.backward_packet_count == 1
    assert updated.byte_count == updated.backward_byte_count == 70
    assert updated.syn_count == updated.ack_count == 1 and updated.duration == 1
    assert updated.state == flow.state


@pytest.mark.parametrize("changes", [
    {"captured_length": -1}, {"captured_length": True}, {"captured_length": 1.5},
    {"timestamp": datetime(2026, 10, 9)}, {"timestamp": "bad"}, {"direction": "sideways"},
    {"flags": ("BOGUS",)}, {"flags": ([],)}, {"flags": None},
])
def test_invalid_statistics_input_cannot_partially_mutate_original_record(changes):
    flow = make_flow(packet_count=5, byte_count=400)
    before = deepcopy(flow.to_dict())
    values = {"direction": FlowDirection.FORWARD, "timestamp": flow.start_time, "captured_length": 54, "flags": ()}
    values.update(changes)
    with pytest.raises((ValueError, TypeError)):
        update_statistics(flow, **values)
    assert flow.to_dict() == before


def test_statistics_helper_uses_elapsed_utc_time_across_daylight_saving_fold():
    local = ZoneInfo("America/New_York")
    flow = make_flow(start_time=datetime(2026, 11, 1, 1, 50, tzinfo=local, fold=0),
                     last_seen=datetime(2026, 11, 1, 1, 50, tzinfo=local, fold=0))
    updated = update_statistics(flow, direction=FlowDirection.FORWARD,
                                timestamp=datetime(2026, 11, 1, 1, 10, tzinfo=local, fold=1), captured_length=54)
    assert updated.duration == 1200 and updated.to_dict()["last_seen"] == "2026-11-01T06:10:00.000000Z"


def test_udp_statistics_helper_does_not_interpret_tcp_flags():
    flow = make_flow(protocol=FlowProtocol.UDP, state=None)
    updated = update_statistics(flow, direction=FlowDirection.FORWARD, timestamp=flow.start_time,
                                captured_length=42, flags=("SYN", "ACK"))
    assert updated.packet_count == 1 and updated.byte_count == 42
    assert updated.syn_count == updated.ack_count == 0 and updated.state is None


@pytest.mark.parametrize("existing", [False, True])
def test_statistics_failure_leaves_table_and_generation_unchanged_and_next_event_continues(monkeypatch, existing):
    tracker = FlowTracker()
    event = prepared()
    if existing:
        tracker.track(event)
    before = tracker.export_flows()

    def fail_statistics(*args, **kwargs):
        raise ValueError("Statistics update failed")

    with monkeypatch.context() as patch:
        patch.setattr("ids.flows.tracker.update_statistics", fail_statistics)
        failed = tracker.track(event)
    assert failed.flow is None and failed.processing_action == "skip_tracking"
    assert failed.errors[-1].stage == "track" and tracker.export_flows() == before
    retried = tracker.track(event)
    key = next(iter(tracker.active_flows))
    assert retried.flow.flow_id == make_flow_id(key, 1)
    assert tracker.export_flows()[0]["packet_count"] == (2 if existing else 1)
