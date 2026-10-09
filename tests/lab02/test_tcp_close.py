"""FIN/ACK evidence, resets, terminal lifetimes and transactional updates."""

from copy import deepcopy

import pytest

from ids.flows.models import FlowDirection, TcpState
from ids.decoders.decoder import decode_event
from ids.flows.tcp import TcpClose, update_close
from ids.flows.tracker import FlowTracker, make_flow_id
from ids.preprocessors.preprocessor import preprocess_event
from tests.lab02.test_flow_statistics import observation
from tests.lab02.test_flow_tracker import prepared
from tests.lab02.test_tcp_handshake import packet


def establish(tracker, base):
    return [tracker.track(packet(base, flags, backward)) for flags, backward in [
        (["SYN"], False), (["SYN", "ACK"], True), (["ACK"], False),
    ]]


def close_normally(tracker, base, backward=False):
    return [tracker.track(packet(base, flags, direction)) for flags, direction in [
        (["FIN", "ACK"], backward), (["ACK"], not backward),
        (["FIN", "ACK"], not backward), (["ACK"], backward),
    ]]


@pytest.mark.parametrize("backward", [False, True])
def test_four_packet_close_in_either_direction_keeps_identity_and_snapshots(backward):
    tracker, base = FlowTracker(), prepared()
    handshake = establish(tracker, base)
    original = [event.to_dict() for event in handshake]
    close = close_normally(tracker, base, backward)
    assert [event.flow.state for event in close] == ["CLOSING", "CLOSING", "CLOSING", "CLOSED"]
    assert len({event.flow.flow_id for event in handshake + close}) == 1
    assert [event.to_dict() for event in handshake] == original
    flow = tracker.export_flows()[0]
    assert flow["state"] == "CLOSED" and flow["packet_count"] == 7 and flow["byte_count"] == 378
    assert (flow["syn_count"], flow["ack_count"], flow["fin_count"], flow["rst_count"]) == (2, 6, 2, 0)
    assert flow["forward_packet_count"] == 4 and flow["backward_packet_count"] == 3
    assert all(event.packet.payload.length == 0 and not event.errors for event in close)


@pytest.mark.parametrize("backward", [False, True])
def test_peer_fin_ack_can_acknowledge_first_fin_and_send_its_own(backward):
    tracker, base = FlowTracker(), prepared()
    establish(tracker, base)
    assert tracker.track(packet(base, ["FIN", "ACK"], backward)).flow.state == "CLOSING"
    assert tracker.track(packet(base, ["FIN", "ACK"], not backward)).flow.state == "CLOSING"
    assert tracker.track(packet(base, ["ACK"], backward)).flow.state == "CLOSED"
    assert tracker.export_flows()[0]["packet_count"] == 6


@pytest.mark.parametrize("rows", [
    [(["FIN", "ACK"], False)],
    [(["FIN", "ACK"], False), (["ACK"], True)],
    [(["FIN", "ACK"], False), (["FIN", "ACK"], False), (["ACK"], True)],
    [(["ACK"], True), (["FIN"], False), (["FIN"], True), (["ACK"], False)],
    [(["FIN"], False), (["FIN"], True), (["ACK"], False)],
    [(["FIN", "ACK"], False), (["FIN", "ACK"], True), (["ACK"], True)],
    [(["FIN", "ACK"], False), (["FIN", "ACK"], True), ([], False)],
    [(["FIN", "ACK"], False), (["SYN", "ACK"], True)],
])
def test_missing_wrong_direction_or_early_ack_never_fabricates_closed(rows):
    tracker, base = FlowTracker(), prepared()
    establish(tracker, base)
    for flags, backward in rows:
        event = tracker.track(packet(base, flags, backward))
    assert event.flow.state == "CLOSING"


def test_both_unacknowledged_fins_need_opposite_acks():
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["FIN"]))
    tracker.track(packet(base, ["FIN"], True))
    assert tracker.track(packet(base, ["ACK"], True)).flow.state == "CLOSING"
    assert tracker.track(packet(base, ["ACK"])).flow.state == "CLOSED"


def test_fin_retransmissions_do_not_replace_the_missing_opposite_fin_or_erase_ack():
    tracker, base = FlowTracker(), prepared()
    establish(tracker, base)
    tracker.track(packet(base, ["FIN", "ACK"]))
    tracker.track(packet(base, ["ACK"], True))
    for _ in range(3):
        assert tracker.track(packet(base, ["FIN", "ACK"])).flow.state == "CLOSING"
    tracker.track(packet(base, ["FIN", "ACK"], True))
    assert tracker.track(packet(base, ["ACK"])).flow.state == "CLOSED"
    flow = tracker.export_flows()[0]
    assert flow["fin_count"] == 5 and flow["packet_count"] == 10


def test_half_closed_data_and_duplicate_final_ack_keep_same_flow_and_count_bytes():
    tracker, base = FlowTracker(), prepared()
    establish(tracker, base)
    first = tracker.track(packet(base, ["FIN", "ACK"]))
    data = packet(base, ["PSH", "ACK"], True)
    data.packet.payload.length = 4
    data.packet.payload.base64 = "ZGF0YQ=="
    data = observation(data, flags=["PSH", "ACK"], length=58)
    assert tracker.track(data).flow.state == "CLOSING"
    tracker.track(packet(base, ["FIN", "ACK"], True))
    last = tracker.track(packet(base, ["ACK"]))
    duplicate = tracker.track(packet(base, ["ACK"]))
    assert last.flow.state == duplicate.flow.state == "CLOSED"
    assert first.flow.flow_id == duplicate.flow.flow_id
    assert tracker.export_flows()[0]["byte_count"] == 436


@pytest.mark.parametrize("stage", ["new", "handshake", "established", "closing"])
@pytest.mark.parametrize("backward", [False, True])
def test_rst_terminates_any_nonterminal_state_without_waiting_for_ack(stage, backward):
    tracker, base = FlowTracker(), prepared()
    if stage == "new":
        tracker.track(packet(base, ["ACK"]))
    elif stage == "handshake":
        tracker.track(packet(base, ["SYN"]))
    else:
        establish(tracker, base)
        if stage == "closing":
            tracker.track(packet(base, ["FIN", "ACK"]))
    previous = tracker.export_flows()[0]
    result = tracker.track(packet(base, ["RST"], backward))
    assert result.flow.state == "RESET" and result.flow.flow_id == previous["flow_id"]
    flow = tracker.export_flows()[0]
    assert flow["packet_count"] == previous["packet_count"] + 1 and flow["rst_count"] == 1


@pytest.mark.parametrize("flags", [["RST"], ["RST", "ACK"], ["RST", "FIN", "ACK"], ["SYN", "RST"]])
def test_first_packet_rst_or_conflicting_flags_prioritize_reset(flags):
    tracker, base = FlowTracker(), prepared()
    assert tracker.track(packet(base, flags)).flow.state == "RESET"
    flow = tracker.export_flows()[0]
    assert flow["packet_count"] == 1 and flow["rst_count"] == 1
    assert flow["fin_count"] == int("FIN" in flags)


@pytest.mark.parametrize("stage", ["closed", "reset"])
@pytest.mark.parametrize("flags", [["ACK"], ["PSH", "ACK"], ["FIN", "ACK"], ["RST"], ["SYN", "ACK"], []])
def test_late_packets_keep_terminal_state_and_lifetime(stage, flags):
    tracker, base = FlowTracker(), prepared()
    if stage == "closed":
        close_normally(tracker, base)
    else:
        tracker.track(packet(base, ["RST"]))
    before = tracker.export_flows()[0]
    result = tracker.track(packet(base, flags))
    assert result.flow.state == before["state"] and result.flow.flow_id == before["flow_id"]
    assert len(tracker.export_flows()) == 1 and tracker.drain_completed_flows() == []
    assert tracker.export_flows()[0]["packet_count"] == before["packet_count"] + 1


@pytest.mark.parametrize("stage", ["closed", "reset"])
@pytest.mark.parametrize("backward", [False, True])
def test_bare_syn_after_terminal_starts_fresh_generation_and_retains_old_summary(stage, backward):
    tracker, base = FlowTracker(), prepared()
    if stage == "closed":
        close_normally(tracker, base)
    else:
        tracker.track(packet(base, ["RST"]))
    old = tracker.export_flows()[0]
    old_key = next(iter(tracker.active_flows))
    result = tracker.track(packet(base, ["SYN"], backward))
    assert result.flow.flow_id == make_flow_id(old_key, 2) and result.flow.state == "HANDSHAKE"
    assert result.flow.direction == "forward"  # first sender of the new lifetime
    active = next(iter(tracker.active_flows.values()))
    assert active.packet_count == 1 and active.byte_count == 54 and active.fin_count == active.rst_count == 0
    assert active.endpoint_a.ip == (base.packet.network.dst_ip if backward else base.packet.network.src_ip)
    exported = {flow["flow_id"]: flow for flow in tracker.export_flows()}
    assert exported[old["flow_id"]] == old and len(exported) == 2
    # No inherited close evidence; finish the new handshake in its own orientation.
    tracker.track(packet(base, ["SYN", "ACK"], not backward))
    assert tracker.track(packet(base, ["ACK"], backward)).flow.state == "ESTABLISHED"
    assert tracker.drain_completed_flows() == [old]
    assert tracker.drain_completed_flows() == [] and len(tracker.export_flows()) == 1


def test_completed_export_and_drain_views_are_detached_and_multiple_lifetimes_preserved():
    tracker, base = FlowTracker(), prepared()
    ids = []
    for _ in range(3):
        tracker.track(packet(base, ["SYN"]))
        terminal = tracker.track(packet(base, ["RST"]))
        ids.append(terminal.flow.flow_id)
    assert len(set(ids)) == 3 and len(tracker.active_flows) == 1
    view = tracker.export_flows()
    view[0]["endpoint_a"]["port"] = 1
    assert all(flow["endpoint_a"]["port"] == 51000 for flow in tracker.export_flows())
    drained = tracker.drain_completed_flows()
    assert [flow["flow_id"] for flow in drained] == ids[:2]
    drained[0]["packet_count"] = 999
    assert tracker.export_flows()[0]["flow_id"] == ids[-1]
    assert tracker.export_flows()[0]["packet_count"] == 2


def test_concurrent_close_reset_and_udp_do_not_share_evidence():
    tracker, first, second = FlowTracker(), prepared(), prepared(sport=51001)
    tracker.track(packet(first, ["FIN", "ACK"]))
    tracker.track(packet(second, ["FIN", "ACK"], True))
    assert tracker.track(packet(first, ["ACK"])).flow.state == "CLOSING"
    assert tracker.track(packet(second, ["ACK"], True)).flow.state == "CLOSING"
    assert tracker.track(packet(first, ["RST"])).flow.state == "RESET"
    assert tracker.track(packet(second, ["ACK"])).flow.state == "CLOSING"
    assert tracker.track(prepared(protocol="UDP")).flow.state is None
    assert len(tracker._tcp_closes) == 2


def test_remove_clears_close_and_handshake_context_and_returns_detached_summary():
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["FIN", "ACK"]))
    key = next(iter(tracker.active_flows))
    summary = tracker.remove_flow(key)
    assert summary.state == "CLOSING" and not tracker._tcp_closes and not tracker._tcp_handshakes
    assert tracker.track(packet(base, ["ACK"])).flow.state == "NEW"
    summary.state = TcpState.CLOSED
    assert tracker.export_flows()[0]["state"] == "NEW"


def test_missing_flags_in_closing_do_not_invent_final_ack():
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["FIN", "ACK"]))
    tracker.track(packet(base, ["FIN", "ACK"], True))
    base.packet.transport.fields = {}
    missing = preprocess_event(decode_event(base.packet))
    assert tracker.track(missing).flow.state == "CLOSING"
    assert tracker.track(packet(base, ["ACK"])).flow.state == "CLOSED"


def test_syn_during_closing_keeps_lifetime_and_cannot_return_to_handshake():
    tracker, base = FlowTracker(), prepared()
    first = tracker.track(packet(base, ["FIN"]))
    later = tracker.track(packet(base, ["SYN"], True))
    assert later.flow.state == "CLOSING" and later.flow.flow_id == first.flow.flow_id
    assert len(tracker.export_flows()) == 1 and tracker.drain_completed_flows() == []


def test_skipped_new_syn_after_reset_cannot_archive_or_replace_terminal_lifetime():
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["RST"]))
    before = snapshot(tracker)
    skipped = packet(base, ["SYN"])
    skipped.processing_action = "skip_tracking"
    assert tracker.track(skipped).flow is None and snapshot(tracker) == before


def test_close_uses_observation_order_and_preserves_caller_views_and_time_bounds():
    tracker, base = FlowTracker(), prepared()
    tracker.track(observation(packet(base, ["FIN", "ACK"]), timestamp="2026-10-09T00:00:02Z"))
    tracker.track(observation(packet(base, ["FIN", "ACK"], True), timestamp="2026-10-09T00:00:04Z"))
    final = observation(packet(base, ["ACK"]), timestamp="2026-10-09T00:00:01Z")
    original = final.to_dict()
    saved = tracker.track(final).to_dict()
    assert saved["flow"]["state"] == "CLOSED" and final.to_dict() == original
    assert {key: value for key, value in saved.items() if key != "flow"} == {
        key: value for key, value in original.items() if key != "flow"
    }
    flow = tracker.export_flows()[0]
    assert flow["start_time"] == "2026-10-09T00:00:01.000000Z"
    assert flow["last_seen"] == "2026-10-09T00:00:04.000000Z" and flow["duration"] == 3


@pytest.mark.parametrize("flags", [["FIN", "ACK"], ["RST"], ["SYN"]])
def test_skip_or_bad_metadata_changes_no_context_record_generation_or_queue(flags):
    tracker, base = FlowTracker(), prepared()
    tracker.track(packet(base, ["FIN", "ACK"]))
    before = snapshot(tracker)
    skipped = packet(base, flags, True)
    skipped.processing_action = "skip_tracking"
    assert tracker.track(skipped).flow is None
    invalid = packet(base, flags, True)
    invalid.normalized["captured_length"] = -1
    assert tracker.track(invalid).flow is None and snapshot(tracker) == before


def snapshot(tracker):
    return (tracker.export_flows(), deepcopy(tracker._tcp_handshakes), deepcopy(tracker._tcp_closes),
            dict(tracker._generations), deepcopy(tracker._completed_flows))


@pytest.mark.parametrize("stage", ["first", "fin", "reset", "final_ack", "reopen"])
@pytest.mark.parametrize("failing_stage", ["update_statistics", "update_handshake", "update_close"])
def test_failed_update_is_atomic_including_terminal_rollover(monkeypatch, stage, failing_stage):
    tracker, base = FlowTracker(), prepared()
    if stage in ("fin", "reset"):
        establish(tracker, base)
    elif stage == "final_ack":
        tracker.track(packet(base, ["FIN", "ACK"]))
        tracker.track(packet(base, ["FIN", "ACK"], True))
    elif stage == "reopen":
        tracker.track(packet(base, ["RST"]))
    flags = {"first": ["FIN"], "fin": ["FIN"], "reset": ["RST"], "final_ack": ["ACK"], "reopen": ["SYN"]}[stage]
    candidate = packet(base, flags)
    original, before = candidate.to_dict(), snapshot(tracker)

    def fail(*args, **kwargs):
        raise ValueError("Injected transition failure")

    with monkeypatch.context() as patch:
        patch.setattr("ids.flows.tracker." + failing_stage, fail)
        failed = tracker.track(candidate)
    assert failed.flow is None and failed.processing_action == "skip_tracking" and failed.errors[-1].stage == "track"
    assert candidate.to_dict() == original and snapshot(tracker) == before
    expected = {"first": "CLOSING", "fin": "CLOSING", "reset": "RESET", "final_ack": "CLOSED", "reopen": "HANDSHAKE"}[stage]
    assert tracker.track(candidate).flow.state == expected
    assert len(tracker.export_flows()) == (2 if stage == "reopen" else 1)


@pytest.mark.parametrize("flags", [None, "FIN", ["invalid"], [True]])
def test_pure_close_handler_rejects_malformed_flags(flags):
    context = TcpClose()
    with pytest.raises(ValueError):
        update_close(TcpState.ESTABLISHED, context, direction=FlowDirection.FORWARD, flags=flags)
    assert context == TcpClose()


def test_pure_close_handler_requires_typed_context():
    with pytest.raises(TypeError):
        update_close(TcpState.NEW, {}, direction=FlowDirection.FORWARD, flags=())


def test_pure_close_handler_keeps_input_immutable_and_flags_do_not_act_as_counters():
    original = TcpClose()
    state, context = update_close(TcpState.NEW, original, direction=FlowDirection.FORWARD, flags=("FIN", "FIN"))
    assert state == "CLOSING" and context.forward_fin and original == TcpClose()
    assert not context.forward_fin_acked and not context.backward_fin
