"""T08: reversed 5-tuples share identity and follow first-observed direction."""

import argparse
import json
from pathlib import Path

from ids.config import load_config
from tests.lab02.flow_pcap_support import summarize, track_pcap, write_transport_pcap


FLOW_ID = "flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2"
SCENARIOS = [
    ("TCP", "10.0.0.2", 51000, "10.0.0.1", 8080),
    ("TCP", "10.0.0.1", 8080, "10.0.0.2", 51000),
    ("TCP", "10.0.0.2", 51000, "10.0.0.1", 8080),
    ("TCP", "10.0.0.1", 8080, "10.0.0.2", 51000),
    ("TCP", "10.0.0.2", 51000, "10.0.0.1", 8080),
]
EXPECTED_FLOW = {
    "flow_id": FLOW_ID, "protocol": "TCP", "application_protocol": "UNKNOWN",
    "endpoint_a": {"ip": "10.0.0.2", "port": 51000},
    "endpoint_b": {"ip": "10.0.0.1", "port": 8080},
    "start_time": "2026-10-09T00:00:00.000000Z", "last_seen": "2026-10-09T00:00:00.000000Z",
    "duration": 0.0, "state": "NEW", "packet_count": 0, "byte_count": 0,
    "forward_packet_count": 0, "forward_byte_count": 0, "backward_packet_count": 0, "backward_byte_count": 0,
    "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
}
EXPECTED = {
    "events": [
        {"packet_id": index + 1, "action": "track", "status": "valid",
         "flow": {"flow_id": FLOW_ID, "direction": direction, "state": "NEW"}}
        for index, direction in enumerate(("forward", "backward", "forward", "backward", "forward"))
    ],
    "flows": [EXPECTED_FLOW],
}


def reproduce(directory: Path) -> tuple[list[dict], list[dict]]:
    input_path = directory / "input.pcap"
    write_transport_pcap(input_path, SCENARIOS)
    default_config = Path(__file__).resolve().parents[2] / "config/default.toml"
    config_path = directory / "config.toml"
    config_path.write_text(default_config.read_text(), encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n", encoding="utf-8")
    events, flows = track_pcap(input_path, directory / "actual.jsonl", directory / "flows.json", load_config(config_path))
    if {"events": summarize(events), "flows": flows} != EXPECTED:
        raise AssertionError("T08 flow identity/direction does not match independent expected values")
    if any(event["errors"] or event["reason"] for event in events):
        raise AssertionError("T08 valid transport packets should not have processing errors")
    return events, flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T08 bidirectional flow")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T08")
    events, flows = reproduce(parser.parse_args().output_dir)
    for event in events:
        print(f"packet {event['packet']['packet_id']}: {event['flow']['direction']}; {event['flow']['flow_id']}")
    print(f"T08 PASS: {len(events)} packets; {len(flows)} flow; first sender A differs from key sort order")


if __name__ == "__main__":
    main()
