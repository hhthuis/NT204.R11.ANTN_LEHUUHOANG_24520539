"""T09: independent FIN-close and RST-reset PCAPs with exact expectations."""

import argparse
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap

from ids.config import load_config
from tests.lab02.flow_pcap_support import summarize, track_pcap


FLOW_ID = "flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2"
HANDSHAKE = [(False, "S", 1000, 0), (True, "SA", 5000, 1001), (False, "A", 1001, 5001)]
# backward, flags, sequence, acknowledgment; every packet has empty payload.
ROWS = {
    "fin": HANDSHAKE + [
        (False, "FA", 1001, 5001), (True, "A", 5001, 1002),
        (True, "FA", 5001, 1002), (False, "A", 1002, 5002),
    ],
    "rst": HANDSHAKE + [(True, "RA", 5001, 1001)],
}
ASSOCIATIONS = {
    "fin": [("forward", "HANDSHAKE"), ("backward", "HANDSHAKE"),
            ("forward", "ESTABLISHED"), ("forward", "CLOSING"),
            ("backward", "CLOSING"), ("backward", "CLOSING"), ("forward", "CLOSED")],
    "rst": [("forward", "HANDSHAKE"), ("backward", "HANDSHAKE"),
            ("forward", "ESTABLISHED"), ("backward", "RESET")],
}
BASE_FLOW = {
    "flow_id": FLOW_ID, "protocol": "TCP", "application_protocol": "UNKNOWN",
    "endpoint_a": {"ip": "10.0.0.2", "port": 51000},
    "endpoint_b": {"ip": "10.0.0.1", "port": 8080},
    "start_time": "2026-10-09T00:00:00.000000Z", "syn_count": 2,
}
FINAL = {
    "fin": {
        "last_seen": "2026-10-09T00:00:00.600000Z", "duration": 0.6,
        "state": "CLOSED", "packet_count": 7, "byte_count": 378,
        "forward_packet_count": 4, "forward_byte_count": 216,
        "backward_packet_count": 3, "backward_byte_count": 162,
        "ack_count": 6, "fin_count": 2, "rst_count": 0,
    },
    "rst": {
        "last_seen": "2026-10-09T00:00:00.300000Z", "duration": 0.3,
        "state": "RESET", "packet_count": 4, "byte_count": 216,
        "forward_packet_count": 2, "forward_byte_count": 108,
        "backward_packet_count": 2, "backward_byte_count": 108,
        "ack_count": 3, "fin_count": 0, "rst_count": 1,
    },
}
EXPECTED = {
    case: {
        "events": [{"packet_id": index + 1, "action": "track", "status": "valid",
                    "flow": {"flow_id": FLOW_ID, "direction": direction, "state": state}}
                   for index, (direction, state) in enumerate(associations)],
        "flows": [{**BASE_FLOW, **FINAL[case]}],
    }
    for case, associations in ASSOCIATIONS.items()
}


def generate_input_pcap(path: Path, case: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    start = Decimal(str(datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()))
    packets = []
    for index, (backward, flags, seq, ack) in enumerate(ROWS[case]):
        src, sport, dst, dport = ("10.0.0.1", 8080, "10.0.0.2", 51000) if backward else ("10.0.0.2", 51000, "10.0.0.1", 8080)
        source_mac, dest_mac = ("02:00:00:00:00:01", "02:00:00:00:00:02") if backward else ("02:00:00:00:00:02", "02:00:00:00:00:01")
        packet = Ether(src=source_mac, dst=dest_mac) / IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
        )
        packet.time = start + Decimal(index) / 10
        packets.append(packet)
    wrpcap(str(path), packets)


def reproduce_case(directory: Path, case: str) -> tuple[list[dict], list[dict]]:
    input_path = directory / "input.pcap"
    generate_input_pcap(input_path, case)
    default_config = Path(__file__).resolve().parents[2] / "config/default.toml"
    config_path = directory / "config.toml"
    config_path.write_text(default_config.read_text(), encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(EXPECTED[case], indent=2) + "\n", encoding="utf-8")
    events, flows = track_pcap(input_path, directory / "actual.jsonl", directory / "flows.json", load_config(config_path))
    if {"events": summarize(events), "flows": flows} != EXPECTED[case]:
        raise AssertionError(f"T09 {case} states/identity/statistics do not match independent expectations")
    assert all(event["packet"]["payload"]["length"] == 0 and event["packet"]["captured_length"] == 54 for event in events)
    assert all(event["errors"] == [] and event["reason"] is None for event in events)
    return events, flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T09 FIN close and RST reset")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T09")
    directory = parser.parse_args().output_dir
    for case in ROWS:
        events, flows = reproduce_case(directory / case, case)
        print(f"T09 {case}: " + " → ".join(event["flow"]["state"] for event in events))
        flow = flows[0]
        print(f"  1 {flow['state']} flow; packets={flow['packet_count']}, bytes={flow['byte_count']}; "
              f"SYN/ACK/FIN/RST={flow['syn_count']}/{flow['ack_count']}/{flow['fin_count']}/{flow['rst_count']}")
    print("T09 PASS: FIN close and RST reset; same flow ID within each independent capture; all payloads empty")


if __name__ == "__main__":
    main()
