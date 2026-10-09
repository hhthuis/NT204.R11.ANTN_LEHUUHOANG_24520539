"""T13: exact packet/byte/flag/time statistics from a mixed transport PCAP."""

import argparse
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

from ids.config import load_config
from tests.lab02.flow_pcap_support import summarize, track_pcap


TCP_ID = "flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2"
UDP_ID = "flow-49eea37761fea07cb47284081a58798c70134ddc017ab8c4eb2ab5b048217879"
REQUEST = b"GET /stats HTTP/1.1\r\nHost: example.test\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
# protocol, reverse direction, flags, sequence, acknowledgment, payload, timestamp offset
ROWS = [
    ("TCP", False, "S", 1000, 0, b"", "2.000000"),
    ("TCP", True, "SA", 5000, 1001, b"", "2.100000"),
    ("TCP", False, "A", 1001, 5001, b"", "2.200000"),
    ("TCP", False, "PA", 1001, 5001, REQUEST, "2.300000"),
    ("TCP", True, "PA", 5001, 1044, RESPONSE, "2.400000"),
    ("TCP", True, "A", 5001, 1001, b"", "1.000000"),
    ("TCP", False, "PA", 1001, 5001, REQUEST, "2.450000"),
    ("TCP", False, "FA", 1044, 5067, b"", "2.500000"),
    ("TCP", True, "RA", 5067, 1045, b"", "2.600000"),
    ("UDP", False, "", 0, 0, b"hello", "3.000000"),
    ("ICMP", False, "", 0, 0, b"", "99.000000"),
    ("UDP", True, "", 0, 0, b"reply!", "1.500000"),
    ("UDP", False, "", 0, 0, b"", "3.500000"),
]
CAPTURED_LENGTHS = [54, 54, 54, 97, 120, 54, 97, 54, 54, 47, 42, 48, 42]
ASSOCIATIONS = [
    (TCP_ID, "forward", "HANDSHAKE"), (TCP_ID, "backward", "HANDSHAKE"),
    (TCP_ID, "forward", "ESTABLISHED"), (TCP_ID, "forward", "ESTABLISHED"),
    (TCP_ID, "backward", "ESTABLISHED"), (TCP_ID, "backward", "ESTABLISHED"),
    (TCP_ID, "forward", "ESTABLISHED"), (TCP_ID, "forward", "ESTABLISHED"), (TCP_ID, "backward", "ESTABLISHED"),
    (UDP_ID, "forward", None), (None, None, None),
    (UDP_ID, "backward", None), (UDP_ID, "forward", None),
]
EXPECTED = {
    "events": [
        {"packet_id": index + 1, "action": "track" if flow_id else "skip_tracking",
         "status": "valid" if flow_id else "invalid",
         "flow": {"flow_id": flow_id, "direction": direction, "state": state} if flow_id else None}
        for index, (flow_id, direction, state) in enumerate(ASSOCIATIONS)
    ],
    "flows": [
        {
            "flow_id": TCP_ID, "protocol": "TCP", "application_protocol": "HTTP",
            "endpoint_a": {"ip": "10.0.0.2", "port": 51000}, "endpoint_b": {"ip": "10.0.0.1", "port": 8080},
            "start_time": "2026-10-09T00:00:01.000000Z", "last_seen": "2026-10-09T00:00:02.600000Z",
            "duration": 1.6, "state": "ESTABLISHED", "packet_count": 9, "byte_count": 638,
            "forward_packet_count": 5, "forward_byte_count": 356,
            "backward_packet_count": 4, "backward_byte_count": 282,
            "syn_count": 2, "ack_count": 8, "fin_count": 1, "rst_count": 1,
        },
        {
            "flow_id": UDP_ID, "protocol": "UDP", "application_protocol": "UNKNOWN",
            "endpoint_a": {"ip": "10.0.0.2", "port": 51000}, "endpoint_b": {"ip": "10.0.0.1", "port": 8080},
            "start_time": "2026-10-09T00:00:01.500000Z", "last_seen": "2026-10-09T00:00:03.500000Z",
            "duration": 2.0, "state": None, "packet_count": 3, "byte_count": 137,
            "forward_packet_count": 2, "forward_byte_count": 89,
            "backward_packet_count": 1, "backward_byte_count": 48,
            "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
        },
    ],
}


def generate_input_pcap(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    start = Decimal(str(datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()))
    packets = []
    for protocol, backward, flags, sequence, acknowledgment, payload, offset in ROWS:
        src, sport, dst, dport = ("10.0.0.1", 8080, "10.0.0.2", 51000) if backward else ("10.0.0.2", 51000, "10.0.0.1", 8080)
        if protocol == "TCP":
            layer = TCP(sport=sport, dport=dport, flags=flags, seq=sequence, ack=acknowledgment)
        elif protocol == "UDP":
            layer = UDP(sport=sport, dport=dport)
        else:
            layer = ICMP()
        packet = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src=src, dst=dst) / layer
        if payload:
            packet /= Raw(payload)
        packet.time = start + Decimal(offset)
        packets.append(packet)
    wrpcap(str(path), packets)


def verify_details(events: list[dict], flows: list[dict]) -> None:
    assert [event["packet"]["captured_length"] for event in events] == CAPTURED_LENGTHS
    assert events[3]["packet"]["application"]["protocol"] == "HTTP"
    assert events[3]["packet"]["payload"]["base64"] == events[6]["packet"]["payload"]["base64"]
    assert events[3]["packet"]["transport"]["fields"]["sequence_number"] == events[6]["packet"]["transport"]["fields"]["sequence_number"]
    assert events[10]["packet"]["parse_status"] == "unsupported" and events[10]["reason"]
    assert events[10]["normalized"]["timestamp"] == "2026-10-09T00:01:39.000000Z"
    for index, event in enumerate(events):
        if index != 10:
            assert event["errors"] == [] and event["reason"] is None
    for flow in flows:
        accepted = [event for event in events if event["flow"] and event["flow"]["flow_id"] == flow["flow_id"]]
        assert flow["packet_count"] == len(accepted)
        assert flow["byte_count"] == sum(event["packet"]["captured_length"] for event in accepted)
        assert flow["packet_count"] == flow["forward_packet_count"] + flow["backward_packet_count"]
        assert flow["byte_count"] == flow["forward_byte_count"] + flow["backward_byte_count"]
    assert sum(flow["packet_count"] for flow in flows) == 12
    assert sum(flow["byte_count"] for flow in flows) == 775


def reproduce(directory: Path) -> tuple[list[dict], list[dict]]:
    input_path = directory / "input.pcap"
    generate_input_pcap(input_path)
    default_config = Path(__file__).resolve().parents[2] / "config/default.toml"
    config_path = directory / "config.toml"
    config_path.write_text(default_config.read_text(), encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n", encoding="utf-8")
    events, flows = track_pcap(input_path, directory / "actual.jsonl", directory / "flows.json", load_config(config_path))
    if {"events": summarize(events), "flows": flows} != EXPECTED:
        raise AssertionError("T13 statistics/associations do not match independent expected values")
    verify_details(events, flows)
    return events, flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T13 flow statistics")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T13")
    events, flows = reproduce(parser.parse_args().output_dir)
    for flow in flows:
        print(f"{flow['protocol']}: packets={flow['packet_count']}, bytes={flow['byte_count']}; "
              f"forward={flow['forward_packet_count']}/{flow['forward_byte_count']}, "
              f"backward={flow['backward_packet_count']}/{flow['backward_byte_count']}; duration={flow['duration']}")
    print(f"T13 PASS: {len(events)} packets, 2 flows; TCP flags 2/8/1/1; retransmission counted; skipped ICMP excluded")


if __name__ == "__main__":
    main()
