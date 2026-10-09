"""DNS wire payloads through Parser/Decoder/Preprocessor and the existing tracker."""

from copy import deepcopy

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP

from ids.flows.tracker import FlowTracker
from tests.lab02.udp_dns_support import make_dns_packet, prepare_packet


def test_dns_query_response_share_one_udp_flow_and_exact_captured_statistics():
    tracker = FlowTracker()
    query = prepare_packet(make_dns_packet())
    response = prepare_packet(make_dns_packet(response=True, offset="0.2"), 2)
    inputs = [query.to_dict(), response.to_dict()]
    events = [tracker.track(query), tracker.track(response)]
    assert [event.flow.direction for event in events] == ["forward", "backward"]
    assert events[0].flow.flow_id == events[1].flow.flow_id
    assert all(event.flow.state is None and event.preprocess_status == "valid" for event in events)
    assert [query.to_dict(), response.to_dict()] == inputs
    for event, original in zip(events, inputs):
        saved = event.to_dict()
        assert {key: value for key, value in saved.items() if key != "flow"} == {
            key: value for key, value in original.items() if key != "flow"
        }
    flow = tracker.export_flows()[0]
    assert flow["protocol"] == "UDP" and flow["application_protocol"] == "DNS"
    assert (flow["packet_count"], flow["byte_count"]) == (2, 172)
    assert (flow["forward_packet_count"], flow["forward_byte_count"]) == (1, 72)
    assert (flow["backward_packet_count"], flow["backward_byte_count"]) == (1, 100)
    assert flow["duration"] == 0.2 and all(flow[key] == 0 for key in ("syn_count", "ack_count", "fin_count", "rst_count"))
    assert tracker._tcp_handshakes == tracker._tcp_closes == {} and tracker.drain_completed_flows() == []


def test_multiple_transaction_ids_and_retransmitted_query_count_each_observation_in_same_flow():
    tracker = FlowTracker()
    specifications = [(False, 0x1234), (False, 0x1234), (True, 0x1234), (False, 0x2345), (True, 0x2345)]
    events = [tracker.track(prepare_packet(make_dns_packet(response=response, transaction_id=identifier, offset=str(index / 10)), index + 1))
              for index, (response, identifier) in enumerate(specifications)]
    assert len({event.flow.flow_id for event in events}) == 1
    assert [event.packet.application.fields["transaction_id"] for event in events] == [0x1234, 0x1234, 0x1234, 0x2345, 0x2345]
    assert events[0].packet.payload.base64 == events[1].packet.payload.base64
    flow = tracker.export_flows()[0]
    assert (flow["packet_count"], flow["byte_count"]) == (5, 416)
    assert (flow["forward_packet_count"], flow["forward_byte_count"]) == (3, 216)
    assert (flow["backward_packet_count"], flow["backward_byte_count"]) == (2, 200)
    assert flow["duration"] == 0.4


def test_different_domain_does_not_change_udp_flow_key():
    tracker = FlowTracker()
    first = tracker.track(prepare_packet(make_dns_packet(name="example.test.")))
    second = tracker.track(prepare_packet(make_dns_packet(name="another.test.", transaction_id=2)))
    assert first.flow.flow_id == second.flow.flow_id and len(tracker.active_flows) == 1
    assert second.normalized["application"]["fields"]["questions"][0]["name"] == "another.test"


def test_capture_starting_with_response_uses_first_sender_orientation_without_client_guess():
    tracker = FlowTracker()
    response = tracker.track(prepare_packet(make_dns_packet(response=True)))
    query = tracker.track(prepare_packet(make_dns_packet(offset="0.2")))
    assert response.flow.flow_id == query.flow.flow_id
    assert response.flow.direction == "forward" and query.flow.direction == "backward"
    flow = tracker.export_flows()[0]
    assert flow["endpoint_a"] == {"ip": "10.0.0.1", "port": 53}
    assert (flow["forward_byte_count"], flow["backward_byte_count"]) == (100, 72)


@pytest.mark.parametrize("change", [
    {"client_ip": "10.0.0.3"}, {"server_ip": "10.0.0.53"},
    {"client_port": 53001}, {"server_port": 5353},
])
def test_changed_endpoint_or_port_separates_dns_flows_and_matches_its_own_reverse(change):
    tracker = FlowTracker()
    first = tracker.track(prepare_packet(make_dns_packet()))
    changed = tracker.track(prepare_packet(make_dns_packet(**change)))
    assert first.flow.flow_id != changed.flow.flow_id and len(tracker.active_flows) == 2
    reply = tracker.track(prepare_packet(make_dns_packet(response=True, **change)))
    assert reply.flow.flow_id == changed.flow.flow_id and reply.flow.direction == "backward"
    assert all(flow["application_protocol"] == "DNS" for flow in tracker.export_flows())


def test_tcp_dns_and_udp_dns_with_same_endpoints_are_separate_flows():
    tracker = FlowTracker()
    udp = make_dns_packet()
    message = bytes(udp[UDP].payload)
    tcp = Ether(src=udp.src, dst=udp.dst) / IP(src=udp[IP].src, dst=udp[IP].dst) / TCP(sport=53000, dport=53, flags="A") / Raw(len(message).to_bytes(2, "big") + message)
    tcp.time = udp.time
    udp_event, tcp_event = tracker.track(prepare_packet(udp)), tracker.track(prepare_packet(tcp))
    assert udp_event.flow.flow_id != tcp_event.flow.flow_id and udp_event.flow.state is None and tcp_event.flow.state == "NEW"
    assert tcp_event.packet.application.protocol == "DNS"
    assert len(tracker.active_flows) == 2 and len(tracker._tcp_closes) == 1


@pytest.mark.parametrize("payload", [b"", b"opaque"])
def test_empty_or_unknown_udp_remains_trackable_and_late_dns_upgrades_application(payload):
    tracker = FlowTracker()
    first = tracker.track(prepare_packet(make_dns_packet(payload=payload)))
    assert first.packet.application.protocol == "UNKNOWN" and first.flow.state is None
    assert tracker.export_flows()[0]["application_protocol"] == "UNKNOWN"
    response = tracker.track(prepare_packet(make_dns_packet(response=True)))
    assert response.flow.flow_id == first.flow.flow_id and tracker.export_flows()[0]["application_protocol"] == "DNS"
    tracker.track(prepare_packet(make_dns_packet(payload=b"")))
    flow = tracker.export_flows()[0]
    assert flow["application_protocol"] == "DNS" and flow["packet_count"] == 3
    assert flow["byte_count"] == 184 + len(payload)


def test_compressed_dns_response_is_parsed_and_counted_using_actual_wire_length():
    tracker = FlowTracker()
    query = tracker.track(prepare_packet(make_dns_packet()))
    response = tracker.track(prepare_packet(make_dns_packet(response=True, compressed=True)))
    assert response.packet.parse_status == "ok" and response.packet.application.kind == "response"
    assert response.normalized["application"]["fields"]["answers"][0]["data"] == "192.0.2.10"
    assert response.packet.captured_length == 88 and query.flow.flow_id == response.flow.flow_id
    assert tracker.export_flows()[0]["byte_count"] == 160


def test_binary_dns_text_decode_diagnostic_is_preserved_and_does_not_block_valid_transport():
    tracker = FlowTracker()
    event = prepare_packet(make_dns_packet(response=True))
    assert event.packet.parse_status == "ok" and event.packet.errors == []
    assert event.decode_status == "partial" and event.preprocess_status == "valid" and event.processing_action == "track"
    assert [error.code for error in event.errors] == ["invalid_character_sequence"]
    assert all(error.stage == "decode" for error in event.errors)
    saved = tracker.track(event)
    assert saved.flow is not None and saved.reason == event.reason and saved.errors == event.errors
    assert "\ufffd" in saved.decoded["payload"]["text"]
    assert saved.packet.payload.base64 == event.packet.payload.base64


def test_dns_domain_normalization_keeps_raw_case_and_answer_address():
    event = prepare_packet(make_dns_packet(response=True))
    assert event.packet.application.fields["questions"][0]["name"] == "Example.Test"
    assert event.packet.application.fields["answers"][0]["name"] == "Example.Test"
    fields = event.normalized["application"]["fields"]
    assert fields["questions"][0]["name"] == fields["answers"][0]["name"] == "example.test"
    assert fields["answers"][0]["data"] == "192.0.2.10"


@pytest.mark.parametrize("existing", [False, True])
def test_skipped_or_bad_udp_metadata_changes_no_statistics_or_context(existing):
    tracker = FlowTracker()
    if existing:
        tracker.track(prepare_packet(make_dns_packet()))
    before = tracker.export_flows()
    skipped = prepare_packet(make_dns_packet(response=True, offset="5.0"))
    skipped.processing_action = "skip_tracking"
    assert tracker.track(skipped).flow is None
    bad = prepare_packet(make_dns_packet(response=True))
    bad.normalized["transport"]["dst_port"] = -1
    assert tracker.track(bad).flow is None and tracker.export_flows() == before
    assert tracker._tcp_handshakes == tracker._tcp_closes == {}


def test_udp_dns_never_calls_tcp_handlers(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("UDP must not call TCP state handlers")

    monkeypatch.setattr("ids.flows.tracker.update_handshake", fail)
    monkeypatch.setattr("ids.flows.tracker.update_close", fail)
    tracker = FlowTracker()
    assert tracker.track(prepare_packet(make_dns_packet())).flow.state is None
    assert tracker.track(prepare_packet(make_dns_packet(response=True))).flow.state is None


@pytest.mark.parametrize("existing", [False, True])
def test_failed_udp_statistics_update_is_atomic_and_next_observation_recovers(monkeypatch, existing):
    tracker = FlowTracker()
    if existing:
        tracker.track(prepare_packet(make_dns_packet()))
    before = tracker.export_flows(), deepcopy(tracker._generations)
    candidate = prepare_packet(make_dns_packet(response=True))

    def fail(*args, **kwargs):
        raise ValueError("Injected statistics failure")

    with monkeypatch.context() as patch:
        patch.setattr("ids.flows.tracker.update_statistics", fail)
        assert tracker.track(candidate).flow is None
    assert (tracker.export_flows(), tracker._generations) == before
    assert tracker.track(candidate).flow is not None
    flow = tracker.export_flows()[0]
    assert flow["packet_count"] == (2 if existing else 1)
    assert flow["byte_count"] == (172 if existing else 100)
