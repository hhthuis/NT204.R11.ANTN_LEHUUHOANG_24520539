import json
import os
import subprocess
import sys
from copy import deepcopy

import pytest
from scapy.all import Ether, IP, TCP, UDP

from ids.config import PreprocessorConfig
from ids.decoders.decoder import decode_event
from ids.flows.models import Endpoint, FlowDirection, FlowKey, FlowProtocol, TcpState
from ids.flows.tracker import FlowTracker, make_flow_id
from ids.models import ApplicationInfo, CaptureSource, ParseError
from ids.pipeline import parse_packet
from ids.preprocessors.preprocessor import preprocess_event
from ids.processing_models import ProcessedEvent
from tests.lab02.preprocessor_case_support import make_event


def prepared(src="10.0.0.2", dst="10.0.0.1", sport=51000, dport=8080, protocol="TCP"):
    packet = make_event(1)
    packet.network.src_ip, packet.network.dst_ip = src, dst
    packet.transport.src_port, packet.transport.dst_port = sport, dport
    packet.transport.protocol = protocol
    return preprocess_event(decode_event(packet))


def reverse(event):
    packet = deepcopy(event.packet)
    packet.network.src_ip, packet.network.dst_ip = packet.network.dst_ip, packet.network.src_ip
    packet.transport.src_port, packet.transport.dst_port = packet.transport.dst_port, packet.transport.src_port
    return preprocess_event(decode_event(packet))


def test_bidirectional_lookup_keeps_first_sender_direction_separate_from_key_sorting():
    tracker = FlowTracker()
    event = prepared()
    forward, backward, again = tracker.track(event), tracker.track(reverse(event)), tracker.track(event)
    assert forward.flow.flow_id == backward.flow.flow_id == again.flow.flow_id
    assert [item.flow.direction for item in (forward, backward, again)] == ["forward", "backward", "forward"]
    key, record = next(iter(tracker.active_flows.items()))
    assert key.endpoint_low.ip == "10.0.0.1" and record.endpoint_a.ip == "10.0.0.2"
    assert record.endpoint_a.port == 51000 and record.endpoint_b.port == 8080
    assert forward.flow.state == "NEW" and len(tracker.active_flows) == 1


def test_starting_with_reverse_packet_changes_orientation_but_not_identity():
    event = prepared()
    first, second = FlowTracker(), FlowTracker()
    result_a = first.track(event)
    result_b = second.track(reverse(event))
    assert result_a.flow.flow_id == result_b.flow.flow_id
    assert result_a.flow.direction == result_b.flow.direction == "forward"
    assert first.track(reverse(event)).flow.direction == second.track(event).flow.direction == "backward"


@pytest.mark.parametrize("change", [
    {"src": "10.0.0.3"}, {"dst": "10.0.0.3"}, {"sport": 51001}, {"dport": 8081}, {"protocol": "UDP"},
])
def test_each_5tuple_component_separates_concurrent_flows(change):
    tracker = FlowTracker()
    first, second = prepared(), prepared(**change)
    associated_a, associated_b = tracker.track(first), tracker.track(second)
    assert associated_a.flow.flow_id != associated_b.flow.flow_id
    assert len(tracker.active_flows) == 2
    assert tracker.track(reverse(first)).flow.flow_id == associated_a.flow.flow_id
    assert tracker.track(reverse(second)).flow.flow_id == associated_b.flow.flow_id


def test_key_encoding_cannot_confuse_endpoint_text_and_port_boundaries():
    first = FlowKey(FlowProtocol.TCP, Endpoint("1.1.1.1", 123), Endpoint("10.0.0.1", 45))
    second = FlowKey(FlowProtocol.TCP, Endpoint("1.1.1.1", 12), Endpoint("10.0.0.1", 345))
    assert make_flow_id(first) != make_flow_id(second)


def test_self_endpoint_has_deterministic_forward_direction():
    tracker = FlowTracker()
    event = prepared(src="127.0.0.1", dst="127.0.0.1", sport=8080, dport=8080)
    assert tracker.track(event).flow.direction == "forward"
    assert tracker.track(reverse(event)).flow.direction == "forward"
    assert len(tracker.active_flows) == 1


def test_identity_is_independent_of_unrelated_flow_creation_order():
    first, second = FlowTracker(), FlowTracker()
    a, b = prepared(), prepared(sport=51001)
    a_first, b_second = first.track(a), first.track(b)
    b_first, a_second = second.track(b), second.track(a)
    assert a_first.flow.flow_id == a_second.flow.flow_id
    assert b_second.flow.flow_id == b_first.flow.flow_id


def test_normalized_protocol_and_ips_are_used_without_editing_raw():
    tracker = FlowTracker()
    event = prepared(src=" 10.0.0.2 ", dst=" 10.0.0.1 ", protocol=" tcp ")
    result = tracker.track(event)
    assert result.flow is not None
    assert result.packet.network.src_ip == " 10.0.0.2 "
    assert result.packet.transport.protocol == " tcp "
    assert tracker.track(prepared()).flow.flow_id == result.flow.flow_id


@pytest.mark.parametrize("layer", [TCP(flags="S"), TCP(flags="SA"), TCP(flags="A"), TCP(flags="R"), UDP()])
def test_real_parser_transport_packets_are_associated_without_state_transitions(layer):
    parsed = parse_packet(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / layer, 1, CaptureSource("pcap", "synthetic.pcap"))
    event = preprocess_event(decode_event(parsed))
    result = FlowTracker().track(event)
    assert result.flow.state == ("NEW" if parsed.transport.protocol == "TCP" else None)
    assert result.decode_status == "skipped" and result.flow.direction == "forward"


def test_late_application_protocol_updates_metadata_without_changing_flow_identity():
    first = prepared()
    second = reverse(first)
    second.packet.application = ApplicationInfo("HTTP", "response", {})
    second = preprocess_event(decode_event(second.packet))
    tracker = FlowTracker()
    assert tracker.track(first).flow.flow_id == tracker.track(second).flow.flow_id
    assert len(tracker.active_flows) == 1
    assert next(iter(tracker.active_flows.values())).application_protocol == "HTTP"


def test_new_flow_records_known_application_from_normalized_metadata():
    packet = make_event(1)
    packet.application = ApplicationInfo("HTTP", "response", {})
    tracker = FlowTracker()
    tracker.track(preprocess_event(decode_event(packet)))
    assert tracker.export_flows()[0]["application_protocol"] == "HTTP"


def test_statistics_update_times_and_counters_in_utc():
    event = prepared()
    event.packet.timestamp = "2026-10-09T07:00:00+07:00"
    event = preprocess_event(decode_event(event.packet))
    tracker = FlowTracker()
    tracker.track(event)
    later = reverse(event)
    later.packet.timestamp = "2026-10-09T00:00:02Z"
    tracker.track(preprocess_event(decode_event(later.packet)))
    record = tracker.export_flows()[0]
    assert record["start_time"] == "2026-10-09T00:00:00.000000Z"
    assert record["last_seen"] == "2026-10-09T00:00:02.000000Z"
    assert record["duration"] == 2 and record["packet_count"] == 2 and record["byte_count"] == 108


def test_skipped_event_cannot_create_or_modify_flow_and_clears_stale_association():
    tracker = FlowTracker()
    good = tracker.track(prepared())
    before = tracker.export_flows()
    skipped = deepcopy(good)
    skipped.processing_action = "skip_tracking"
    original = deepcopy(skipped.to_dict())
    result = tracker.track(skipped)
    assert result.flow is None and result.processing_action == "skip_tracking"
    assert tracker.export_flows() == before and skipped.to_dict() == original
    assert result.errors == skipped.errors and result.reason == skipped.reason
    empty = FlowTracker()
    assert empty.track(skipped).flow is None and empty.active_flows == {}


@pytest.mark.parametrize("path, value", [
    (("network",), None), (("network",), []), (("network", "protocol"), "IPv6"),
    (("network", "src_ip"), "bad"), (("network", "src_ip"), " 10.0.0.2 "),
    (("transport",), None), (("transport", "protocol"), "SCTP"),
    (("transport", "src_port"), True), (("transport", "dst_port"), 65536),
    (("transport", "flags"), None), (("transport", "flags"), ["BOGUS"]),
    (("timestamp",), None), (("timestamp",), "bad"), (("timestamp",), "2026-10-09T00:00:00"),
    (("timestamp",), "2026-10-09T07:00:00+07:00"), (("captured_length",), -1),
    (("captured_length",), True),
])
def test_corrupt_authorized_metadata_is_diagnosed_before_table_mutation(path, value):
    event = prepared()
    parent = event.normalized
    for name in path[:-1]:
        parent = parent[name]
    parent[path[-1]] = value
    tracker = FlowTracker()
    result = tracker.track(event)
    assert result.flow is None and result.processing_action == "skip_tracking"
    assert result.errors[-1].stage == "track" and result.errors[-1].code == "tracker_invalid_metadata"
    assert result.reason and tracker.active_flows == {}
    assert tracker.track(prepared()).flow is not None


@pytest.mark.parametrize("status", [None, "invalid", "unrecognized"])
def test_forged_track_action_without_validated_status_cannot_create_flow(status):
    event = prepared()
    event.preprocess_status = status
    tracker = FlowTracker()
    assert tracker.track(event).processing_action == "skip_tracking" and tracker.active_flows == {}


def test_forged_track_action_does_not_bypass_unsafe_raw_fragment():
    event = prepared()
    event.packet.network.fragment_offset = 1
    tracker = FlowTracker()
    assert tracker.track(event).flow is None and tracker.active_flows == {}


def test_forged_track_action_does_not_override_preprocessor_skip_diagnostics():
    packet = make_event(1)
    packet.application.protocol = "FTP"
    event = preprocess_event(decode_event(packet), PreprocessorConfig(unsupported_event_policy="skip"))
    event.processing_action = "track"
    tracker = FlowTracker()
    assert tracker.track(event).flow is None and tracker.active_flows == {}
    marked = preprocess_event(decode_event(packet))
    assert tracker.track(marked).flow is not None
    assert tracker.export_flows()[0]["application_protocol"] == "UNKNOWN"


def test_failed_existing_flow_association_does_not_mutate_table_and_retry_clears_its_diagnostics():
    tracker = FlowTracker()
    event = prepared()
    event.reason = "operator note"
    first = tracker.track(event)
    before = tracker.export_flows()
    event.normalized["timestamp"] = "bad"
    failed = tracker.track(event)
    assert failed.flow is None and tracker.export_flows() == before
    retried = tracker.track(preprocess_event(failed))
    assert retried.flow.flow_id == first.flow.flow_id
    assert retried.errors == [] and retried.reason == "operator note"


def test_tracker_preserves_prior_errors_reason_and_detached_views():
    event = prepared()
    event.packet.parse_status = "partial"
    event.packet.errors = [ParseError("http", "body incomplete")]
    event = preprocess_event(decode_event(event.packet))
    event.reason = "operator note; " + event.reason
    original = deepcopy(event.to_dict())
    tracker = FlowTracker()
    result = tracker.track(event)
    saved = json.loads(json.dumps(result.to_dict()))
    assert event.to_dict() == original
    for field in ("packet", "decoded", "normalized", "errors", "reason", "decode_status", "preprocess_status", "processing_action"):
        assert saved[field] == original[field]
    assert saved["flow"]["direction"] == "forward"
    result.normalized["network"]["src_ip"] = "changed"
    assert event.normalized["network"]["src_ip"] == "10.0.0.2"


def test_flow_inspection_and_export_cannot_mutate_internal_records_or_event_snapshots():
    tracker = FlowTracker()
    associated = tracker.track(prepared())
    snapshot = associated.to_dict()
    view = tracker.active_flows
    record = next(iter(view.values()))
    record.state = TcpState.ESTABLISHED
    record.flow_id = "changed"
    view.clear()
    exported = tracker.export_flows()
    exported[0]["endpoint_a"]["port"] = 1
    exported[0]["flow_id"] = "changed"
    assert associated.to_dict() == snapshot
    assert tracker.track(prepared()).flow.flow_id == associated.flow.flow_id
    assert tracker.track(prepared()).flow.state == "NEW" and len(tracker.active_flows) == 1


def test_remove_and_recreate_key_starts_new_generation_without_mutating_old_event():
    tracker = FlowTracker()
    event = prepared()
    first = tracker.track(event)
    key = next(iter(tracker.active_flows))
    removed = tracker.remove_flow(key)
    assert removed.flow_id == first.flow.flow_id and tracker.active_flows == {}
    assert tracker.remove_flow(key) is None
    second = tracker.track(reverse(event))
    assert second.flow.flow_id != first.flow.flow_id
    assert second.flow.direction == "forward" and first.flow.direction == "forward"
    assert second.flow.flow_id == make_flow_id(key, 2)
    assert first.flow.flow_id == make_flow_id(key, 1)


@pytest.mark.parametrize("generation", [0, -1, True, 1.5])
def test_invalid_generation_is_rejected(generation):
    key = FlowKey(FlowProtocol.TCP, Endpoint("10.0.0.1", 80), Endpoint("10.0.0.2", 51000))
    with pytest.raises(ValueError, match="positive integer"):
        make_flow_id(key, generation)


def test_flow_id_is_stable_across_python_hash_seeds():
    source = (
        "from ids.flows.models import Endpoint, FlowKey, FlowProtocol\n"
        "from ids.flows.tracker import make_flow_id\n"
        "print(make_flow_id(FlowKey(FlowProtocol.TCP, Endpoint('10.0.0.1',80), Endpoint('10.0.0.2',51000))))\n"
    )
    ids = [subprocess.check_output([sys.executable, "-c", source], env={**os.environ, "PYTHONHASHSEED": seed}, text=True).strip() for seed in ("1", "42")]
    assert ids[0] == ids[1] and ids[0].startswith("flow-") and len(ids[0]) == 69


def test_unprocessed_default_event_does_not_create_flow():
    tracker = FlowTracker()
    event = ProcessedEvent(make_event(1))
    assert tracker.track(event).flow is None and tracker.active_flows == {}


def test_wrong_api_object_type_is_a_clear_programming_error():
    with pytest.raises(TypeError, match="ProcessedEvent"):
        FlowTracker().track({})
