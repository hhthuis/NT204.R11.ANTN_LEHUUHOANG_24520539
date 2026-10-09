import base64
import json

from scapy.all import UDP

from ids.capture.pcap import read_pcap
from tests.lab02.reproduce_t10 import EXPECTED, FLOW_ID, diagnostics, dns_views, reproduce


def test_t10_pcap_dns_query_response_share_flow_and_match_wire_bytes_fields_and_diagnostics(tmp_path):
    events, flows = reproduce(tmp_path)
    saved_events = [json.loads(line) for line in (tmp_path / "actual.jsonl").read_text().splitlines()]
    assert saved_events == events
    assert json.loads((tmp_path / "flows.json").read_text()) == flows == EXPECTED["flows"]
    assert json.loads((tmp_path / "expected.json").read_text()) == EXPECTED
    assert dns_views(saved_events) == EXPECTED["dns"] and diagnostics(saved_events) == EXPECTED["diagnostics"]
    assert {event["flow"]["flow_id"] for event in saved_events} == {FLOW_ID}
    assert [event["flow"]["direction"] for event in events] == ["forward", "backward"]
    wire_packets = list(read_pcap(tmp_path / "input.pcap"))
    assert len(wire_packets) == 2 and sum(len(bytes(packet)) for packet in wire_packets) == 172
    for event, packet in zip(events, wire_packets):
        assert base64.b64decode(event["packet"]["payload"]["base64"], validate=True) == bytes(packet[UDP].payload)
        assert event["packet"]["captured_length"] == len(bytes(packet))
    flow = flows[0]
    assert flow["packet_count"] == flow["forward_packet_count"] + flow["backward_packet_count"] == 2
    assert flow["byte_count"] == flow["forward_byte_count"] + flow["backward_byte_count"] == 172
    assert events[1]["decoded"]["payload"]["status"] == "partial"
    assert "\ufffd" in events[1]["decoded"]["payload"]["text"]
