"""T07: three empty-payload SYN → SYN/ACK → ACK packets establish one flow."""

import argparse
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap

from ids.config import load_config
from tests.lab02.flow_pcap_support import summarize, track_pcap


FLOW_ID = "flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2"
EXPECTED = {
    "events": [
        {"packet_id": 1, "action": "track", "status": "valid",
         "flow": {"flow_id": FLOW_ID, "direction": "forward", "state": "HANDSHAKE"}},
        {"packet_id": 2, "action": "track", "status": "valid",
         "flow": {"flow_id": FLOW_ID, "direction": "backward", "state": "HANDSHAKE"}},
        {"packet_id": 3, "action": "track", "status": "valid",
         "flow": {"flow_id": FLOW_ID, "direction": "forward", "state": "ESTABLISHED"}},
    ],
    "flows": [{
        "flow_id": FLOW_ID, "protocol": "TCP", "application_protocol": "UNKNOWN",
        "endpoint_a": {"ip": "10.0.0.2", "port": 51000},
        "endpoint_b": {"ip": "10.0.0.1", "port": 8080},
        "start_time": "2026-10-09T00:00:00.000000Z",
        "last_seen": "2026-10-09T00:00:00.200000Z", "duration": 0.2,
        "state": "ESTABLISHED", "packet_count": 3, "byte_count": 162,
        "forward_packet_count": 2, "forward_byte_count": 108,
        "backward_packet_count": 1, "backward_byte_count": 54,
        "syn_count": 2, "ack_count": 2, "fin_count": 0, "rst_count": 0,
    }],
}


def generate_input_pcap(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    start = Decimal(str(datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()))
    packets = []
    for index, (backward, flags, seq, ack) in enumerate([
        (False, "S", 1000, 0), (True, "SA", 5000, 1001), (False, "A", 1001, 5001),
    ]):
        src, sport, dst, dport = ("10.0.0.1", 8080, "10.0.0.2", 51000) if backward else ("10.0.0.2", 51000, "10.0.0.1", 8080)
        source_mac, dest_mac = ("02:00:00:00:00:01", "02:00:00:00:00:02") if backward else ("02:00:00:00:00:02", "02:00:00:00:00:01")
        packet = Ether(src=source_mac, dst=dest_mac) / IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
        )
        packet.time = start + Decimal(index) / 10
        packets.append(packet)
    wrpcap(str(path), packets)


def reproduce(directory: Path) -> tuple[list[dict], list[dict]]:
    input_path = directory / "input.pcap"
    generate_input_pcap(input_path)
    default_config = Path(__file__).resolve().parents[2] / "config/default.toml"
    config_path = directory / "config.toml"
    config_path.write_text(default_config.read_text(), encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n", encoding="utf-8")
    events, flows = track_pcap(input_path, directory / "actual.jsonl", directory / "flows.json", load_config(config_path))
    if {"events": summarize(events), "flows": flows} != EXPECTED:
        raise AssertionError("T07 state/direction/identity/statistics do not match independent expectations")
    assert [event["packet"]["transport"]["fields"]["flags"] for event in events] == [["SYN"], ["SYN", "ACK"], ["ACK"]]
    assert all(event["packet"]["payload"]["length"] == 0 and event["packet"]["captured_length"] == 54 for event in events)
    assert all(event["errors"] == [] and event["reason"] is None for event in events)
    return events, flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T07 TCP handshake")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T07")
    events, flows = reproduce(parser.parse_args().output_dir)
    for event in events:
        print(f"packet {event['packet']['packet_id']}: {event['flow']['direction']}; {event['flow']['state']}")
    flow = flows[0]
    print(f"T07 PASS: {len(events)} empty-payload packets; 1 ESTABLISHED flow; "
          f"bytes={flow['byte_count']}; SYN={flow['syn_count']}, ACK={flow['ack_count']}")


if __name__ == "__main__":
    main()
