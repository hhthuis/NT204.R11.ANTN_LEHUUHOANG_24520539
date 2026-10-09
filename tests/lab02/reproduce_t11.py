"""T11: interleaved transport flows must never merge distinct 5-tuples."""

import argparse
import json
from pathlib import Path

from ids.config import load_config
from tests.lab02.flow_pcap_support import summarize, track_pcap, write_transport_pcap


FLOW_IDS = {
    "F1": "flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2",
    "F2": "flow-a580772992cdd5c8297ccff00cc8dfbd3870bb28aa48c60467c04ae73b072ff7",
    "F3": "flow-66485b98c78e375cd65022a361f2be0ab9eb9410008a262396d82891e9ebffe5",
    "F4": "flow-49eea37761fea07cb47284081a58798c70134ddc017ab8c4eb2ab5b048217879",
    "F5": "flow-6a4bc05cd39f8e0507daa886aae3744fa791ffc40885b2dac931e04fef98a993",
    "F6": "flow-43e00fc5f543b1de54be40a82a689724e375fcd13c00dfef3d775df540ae49bb",
}
SCENARIOS = [
    ("TCP", "10.0.0.2", 51000, "10.0.0.1", 8080),
    ("TCP", "10.0.0.2", 51001, "10.0.0.1", 8080),
    ("TCP", "10.0.0.2", 51000, "10.0.0.3", 8080),
    ("UDP", "10.0.0.2", 51000, "10.0.0.1", 8080),
    ("TCP", "10.0.0.2", 51000, "10.0.0.1", 8081),
    ("TCP", "10.0.0.4", 51000, "10.0.0.1", 8080),
    ("TCP", "10.0.0.1", 8080, "10.0.0.2", 51000),
    ("UDP", "10.0.0.1", 8080, "10.0.0.2", 51000),
    ("TCP", "10.0.0.1", 8080, "10.0.0.2", 51001),
    ("TCP", "10.0.0.3", 8080, "10.0.0.2", 51000),
    ("TCP", "10.0.0.1", 8081, "10.0.0.2", 51000),
    ("TCP", "10.0.0.1", 8080, "10.0.0.4", 51000),
    ("ICMP", "10.0.0.4", 0, "10.0.0.1", 0),
    ("TCP", "10.0.0.2", 51000, "10.0.0.1", 8080),
    ("UDP", "10.0.0.2", 51000, "10.0.0.1", 8080),
    ("TCP", "10.0.0.1", 8080, "10.0.0.2", 51001),
]
ASSOCIATIONS = [
    ("F1", "forward"), ("F2", "forward"), ("F3", "forward"),
    ("F4", "forward"), ("F5", "forward"), ("F6", "forward"),
    ("F1", "backward"), ("F4", "backward"), ("F2", "backward"),
    ("F3", "backward"), ("F5", "backward"), ("F6", "backward"),
    (None, None), ("F1", "forward"), ("F4", "forward"), ("F2", "backward"),
]
SKIP_ERRORS = [
    "validation_missing_transport", "validation_unsupported_packet", "validation_unsafe_lower_layer_parse",
    "policy_invalid_skip", "policy_unsupported_mark",
]

# Literal statistics from the fixed fixture (TCP frame=54 bytes, UDP=42 bytes).
# last_second, duration, packets, bytes, forward packets/bytes, backward packets/bytes, ACKs.
STATISTICS = {
    "F1": (13, 13.0, 3, 162, 2, 108, 1, 54, 3),
    "F2": (15, 14.0, 3, 162, 1, 54, 2, 108, 3),
    "F3": (9, 7.0, 2, 108, 1, 54, 1, 54, 2),
    "F4": (14, 11.0, 3, 126, 2, 84, 1, 42, 0),
    "F5": (10, 6.0, 2, 108, 1, 54, 1, 54, 2),
    "F6": (11, 6.0, 2, 108, 1, 54, 1, 54, 2),
}


def expected_flow(label, protocol, a_ip, a_port, b_ip, b_port, second) -> dict:
    instant = f"2026-10-09T00:00:{second:02d}.000000Z"
    last_second, duration, packets, byte_count, forward_packets, forward_bytes, backward_packets, backward_bytes, acks = STATISTICS[label]
    return {
        "flow_id": FLOW_IDS[label], "protocol": protocol, "application_protocol": "UNKNOWN",
        "endpoint_a": {"ip": a_ip, "port": a_port}, "endpoint_b": {"ip": b_ip, "port": b_port},
        "start_time": instant, "last_seen": f"2026-10-09T00:00:{last_second:02d}.000000Z", "duration": duration,
        "state": None if protocol == "UDP" else "NEW", "packet_count": packets, "byte_count": byte_count,
        "forward_packet_count": forward_packets, "forward_byte_count": forward_bytes,
        "backward_packet_count": backward_packets, "backward_byte_count": backward_bytes,
        "syn_count": 0, "ack_count": acks, "fin_count": 0, "rst_count": 0,
    }


EXPECTED = {
    "events": [
        {"packet_id": index + 1, "action": "track" if label else "skip_tracking",
         "status": "valid" if label else "invalid", "flow": {
             "flow_id": FLOW_IDS[label], "direction": direction, "state": None if label == "F4" else "NEW",
         } if label else None}
        for index, (label, direction) in enumerate(ASSOCIATIONS)
    ],
    "flows": sorted([
        expected_flow("F1", "TCP", "10.0.0.2", 51000, "10.0.0.1", 8080, 0),
        expected_flow("F2", "TCP", "10.0.0.2", 51001, "10.0.0.1", 8080, 1),
        expected_flow("F3", "TCP", "10.0.0.2", 51000, "10.0.0.3", 8080, 2),
        expected_flow("F4", "UDP", "10.0.0.2", 51000, "10.0.0.1", 8080, 3),
        expected_flow("F5", "TCP", "10.0.0.2", 51000, "10.0.0.1", 8081, 4),
        expected_flow("F6", "TCP", "10.0.0.4", 51000, "10.0.0.1", 8080, 5),
    ], key=lambda flow: flow["flow_id"]),
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
        raise AssertionError("T11 concurrent flows do not match independent expected values")
    for index, event in enumerate(events):
        codes = [error["code"] for error in event["errors"]]
        if codes != (SKIP_ERRORS if index == 12 else []):
            raise AssertionError(f"T11 unexpected processing errors on packet {index + 1}")
    if not events[12]["reason"] or events[-1]["flow"]["flow_id"] != FLOW_IDS["F2"]:
        raise AssertionError("T11 skip reasons or continuation failed")
    return events, flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T11 concurrent flows")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T11")
    events, flows = reproduce(parser.parse_args().output_dir)
    for event, (label, _) in zip(events, ASSOCIATIONS, strict=True):
        direction = event["flow"]["direction"] if event["flow"] else "skip_tracking"
        print(f"packet {event['packet']['packet_id']}: {label or 'ICMP'}; {direction}")
    print(f"T11 PASS: {len(events)} packets; {len(flows)} distinct flows; skipped ICMP adds no flow; processing continues")


if __name__ == "__main__":
    main()
