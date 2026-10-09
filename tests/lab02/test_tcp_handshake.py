"""Capture-order TCP handshake, isolation, snapshots and transactional updates."""

from copy import deepcopy

import pytest

from ids.flows.models import FlowDirection, TcpState
from ids.decoders.decoder import decode_event
from ids.flows.tcp import TcpHandshake, update_handshake
from ids.flows.tracker import FlowTracker, make_flow_id
from ids.preprocessors.preprocessor import preprocess_event
from tests.lab02.test_flow_statistics import observation
from tests.lab02.test_flow_tracker import prepared, reverse


def packet(base, flags, backward=False):
    return observation(reverse(base) if backward else base, flags=flags)


def test_complete_handshake_counts_empty_packets_and_preserves_event_snapshots():
    tracker, base = FlowTracker(), prepared()
    inputs = [packet(base, ["SYN"]), packet(base, ["SYN", "ACK"], True), packet(base, ["ACK"])]
    before = [event.to_dict() for event in inputs]
    events = [tracker.track(event) for event in inputs]
    assert [event.flow.state for event in events] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]
    assert [event.flow.direction for event in events] == ["forward", "backward", "forward"]
    assert len({event.flow.flow_id for event in events}) == 1
    assert [event.to_dict() for event in inputs] == before
    for event, original in zip(events, before):
        saved = event.to_dict()
        assert {key: value for key, value in saved.items() if key != "flow"} == {
            key: value for key, value in original.items() if key != "flow"
        }
        assert event.packet.payload.length == 0
    flow = tracker.export_flows()[0]
    assert (flow["packet_count"], flow["byte_count"]) == (3, 162)
    assert (flow["syn_count"], flow["ack_count"]) == (2, 2)
    assert (flow["forward_packet_count"], flow["backward_packet_count"]) == (2, 1)


@pytest.mark.parametrize("final_flags", [["ACK"], ["ACK", "PSH"], ["ACK", "ECE"]])
def test_initiator_may_be_backward_when_capture_starts_with_server_packet(final_flags):
    tracker, base = FlowTracker(), prepared()
    assert tracker.track(packet(base, ["ACK"])).flow.state == "NEW"
    assert tracker.track(packet(base, ["SYN"], True)).flow.state == "HANDSHAKE"
    assert tracker.track(packet(base, ["SYN", "ACK"])).flow.state == "HANDSHAKE"
    final = tracker.track(packet(base, final_flags, True))
    assert final.flow.state == "ESTABLISHED" and final.flow.direction == "backward"
    flow = tracker.export_flows()[0]
    assert flow["endpoint_a"]["ip"] == base.packet.network.src_ip


@pytest.mark.parametrize("rows, expected", [
    ([(["ACK"], False), (["PSH", "ACK"], True)], "NEW"),
    ([(["SYN", "ACK"], True), (["ACK"], False)], "HANDSHAKE"),
    ([(["SYN"], False), (["ACK"], False)], "HANDSHAKE"),
    ([(["SYN"], False), (["SYN", "ACK"], False), (["ACK"], False)], "HANDSHAKE"),
    ([(["SYN"], False), (["SYN", "ACK"], True), (["ACK"], True)], "HANDSHAKE"),
    ([(["SYN", "ACK"], True), (["SYN"], False), (["ACK"], False)], "HANDSHAKE"),
    ([(["ACK"], False), (["SYN", "ACK"], True), (["SYN"], False)], "HANDSHAKE"),
    ([(["SYN"], False), (["SYN"], True), (["ACK"], False)], "HANDSHAKE"),
])
def test_incomplete_out_of_order_or_wrong_direction_cannot_establish(rows, expected):
    tracker, base = FlowTracker(), prepared()
    for flags, backward in rows:
        result = tracker.track(packet(base, flags, backward))
    assert result.flow.state == expected
    assert tracker.export_flows()[0]["packet_count"] == len(rows)


def test_retransmitted_syn_and_syn_ack_keep_evidence_and_count_each_observation():
    tracker, base = FlowTracker(), prepared()
    for flags, backward in [(["SYN"], False), (["SYN"], False),
                            (["SYN", "ACK"], True), (["SYN", "ACK"], True), (["SYN"], False)]:
        assert tracker.track(packet(base, flags, backward)).flow.state == "HANDSHAKE"
    assert tracker.track(packet(base, ["ACK"])).flow.state == "ESTABLISHED"
    flow = tracker.export_flows()[0]
    assert (flow["packet_count"], flow["syn_count"], flow["ack_count"]) == (6, 5, 3)
    assert len(tracker.active_flows) == 1


@pytest.mark.parametrize("flags", [[], ["PSH"], ["FIN", "ACK"], ["RST", "ACK"], ["SYN", "FIN", "ACK"], ["SYN", "RST"]])
def test_missing_ack_or_close_reset_flags_do_not_complete_handshake(flags):
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["SYN"]))
    tracker.track(packet(base, ["SYN", "ACK"], True))
    assert tracker.track(packet(base, flags)).flow.state == "HANDSHAKE"


def test_missing_flags_remain_trackable_without_inventing_handshake():
    base = prepared()
    base.packet.transport.fields = {}
    result = FlowTracker().track(preprocess_event(decode_event(base.packet)))
    assert result.flow.state == "NEW" and result.preprocess_status == "partial"


@pytest.mark.parametrize("flags", [["ACK"], ["PSH", "ACK"], ["SYN"], ["SYN", "ACK"], [], ["FIN", "ACK"], ["RST", "ACK"]])
def test_established_does_not_regress_and_close_is_deferred(flags):
    tracker, base = FlowTracker(), prepared()
    for step, backward in [(["SYN"], False), (["SYN", "ACK"], True), (["ACK"], False)]:
        tracker.track(packet(base, step, backward))
    assert tracker.track(packet(base, flags)).flow.state == "ESTABLISHED"


def test_concurrent_flows_cannot_share_handshake_evidence_and_udp_has_no_context():
    tracker, first, second = FlowTracker(), prepared(), prepared(sport=51001)
    tracker.track(packet(first, ["SYN"]))
    tracker.track(packet(second, ["SYN", "ACK"], True))
    assert tracker.track(packet(first, ["ACK"])).flow.state == "HANDSHAKE"
    assert tracker.track(packet(second, ["ACK"])).flow.state == "HANDSHAKE"
    tracker.track(packet(first, ["SYN", "ACK"], True))
    assert tracker.track(packet(first, ["ACK"])).flow.state == "ESTABLISHED"
    assert tracker.track(prepared(protocol="UDP")).flow.state is None
    assert len(tracker._tcp_handshakes) == 2 and len(tracker.active_flows) == 3


def test_remove_then_recreate_clears_handshake_and_starts_new_lifetime():
    tracker, base = FlowTracker(), prepared()
    first = tracker.track(packet(base, ["SYN"]))
    tracker.track(packet(base, ["SYN", "ACK"], True))
    key = next(iter(tracker.active_flows))
    removed = tracker.remove_flow(key)
    assert removed.state == "HANDSHAKE" and tracker._tcp_handshakes == {}
    result = tracker.track(packet(base, ["ACK"]))
    assert result.flow.state == "NEW" and result.flow.flow_id == make_flow_id(key, 2)
    assert result.flow.flow_id != first.flow.flow_id
    assert tracker.export_flows()[0]["packet_count"] == 1


def test_skipped_or_invalid_syn_ack_does_not_supply_handshake_evidence():
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["SYN"]))
    before = tracker.export_flows(), deepcopy(tracker._tcp_handshakes)
    skipped = packet(base, ["SYN", "ACK"], True)
    skipped.processing_action = "skip_tracking"
    assert tracker.track(skipped).flow is None
    invalid = packet(base, ["SYN", "ACK"], True)
    invalid.normalized["transport"]["flags"] = ["bogus"]
    assert tracker.track(invalid).flow is None
    assert (tracker.export_flows(), tracker._tcp_handshakes) == before
    assert tracker.track(packet(base, ["ACK"])).flow.state == "HANDSHAKE"


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failing_stage", ["update_statistics", "update_handshake"])
def test_failed_update_commits_neither_context_statistics_nor_generation(monkeypatch, existing, failing_stage):
    tracker, base = FlowTracker(), prepared()
    if existing:
        tracker.track(packet(base, ["SYN"]))
    candidate = packet(base, ["SYN", "ACK"], True) if existing else packet(base, ["SYN"])
    before = tracker.export_flows(), deepcopy(tracker._tcp_handshakes), dict(tracker._generations)

    def fail(*args, **kwargs):
        raise ValueError("Injected update failure")

    with monkeypatch.context() as patch:
        patch.setattr("ids.flows.tracker." + failing_stage, fail)
        failed = tracker.track(candidate)
    assert failed.flow is None and failed.errors[-1].stage == "track"
    assert (tracker.export_flows(), tracker._tcp_handshakes, tracker._generations) == before
    if existing:
        assert tracker.track(packet(base, ["ACK"])).flow.state == "HANDSHAKE"
        tracker.track(candidate)
        assert tracker.track(packet(base, ["ACK"])).flow.state == "ESTABLISHED"
    else:
        assert tracker.track(candidate).flow.state == "HANDSHAKE"
        key = next(iter(tracker.active_flows))
        assert tracker._generations[key] == 1 and tracker.export_flows()[0]["packet_count"] == 1


def test_pure_handler_returns_new_frozen_evidence():
    original = TcpHandshake()
    state, updated = update_handshake(TcpState.NEW, original, direction=FlowDirection.FORWARD, flags=("SYN",))
    assert state == "HANDSHAKE" and updated.initiator == "forward"
    assert original == TcpHandshake() and original is not updated


@pytest.mark.parametrize("flags", [None, "SYN", ["invalid"], [True]])
def test_pure_handler_rejects_malformed_flags_without_mutating_context(flags):
    original = TcpHandshake()
    with pytest.raises(ValueError):
        update_handshake(TcpState.NEW, original, direction=FlowDirection.FORWARD, flags=flags)
    assert original == TcpHandshake()


def test_contradictory_first_syn_flags_do_not_start_handshake():
    tracker, base = FlowTracker(), prepared()
    for flags in (["SYN", "FIN"], ["SYN", "RST"], ["RST", "ACK"]):
        assert tracker.track(packet(base, flags)).flow.state == "NEW"
    assert tracker.export_flows()[0]["packet_count"] == 3
