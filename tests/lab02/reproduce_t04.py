"""Reproducible T04: invalid bytes followed by a valid packet, both policies."""

import argparse
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.capture.pcap import read_pcap
from ids.config import DecoderConfig, load_config
from ids.decoders.decoder import decode_event
from ids.models import CaptureSource
from ids.pipeline import parse_packet


RAW_PAYLOADS = (b"bad utf8: \xff\r\n", b"next valid event\r\n")
EXPECTED = {
    "replace": [
        {
            "packet_id": 1,
            "decode_status": "partial",
            "text": "bad utf8: \ufffd\r\n",
            "error_codes": ["invalid_character_sequence"],
        },
        {
            "packet_id": 2,
            "decode_status": "ok",
            "text": "next valid event\r\n",
            "error_codes": [],
        },
    ],
    "strict": [
        {
            "packet_id": 1,
            "decode_status": "error",
            "text": None,
            "error_codes": ["invalid_character_sequence"],
        },
        {
            "packet_id": 2,
            "decode_status": "ok",
            "text": "next valid event\r\n",
            "error_codes": [],
        },
    ],
}


def generate_input_pcap(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()
    packets = []
    sequence = 1000
    for index, payload in enumerate(RAW_PAYLOADS):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000, dport=9999, flags="PA", seq=sequence)
            / Raw(payload)
        )
        packet.time = start + index
        packets.append(packet)
        sequence += len(payload)
    wrpcap(str(path), packets)


def decode_pcap(
    input_path: Path, output_path: Path, config: DecoderConfig
) -> list[dict]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source = CaptureSource("pcap", input_path.name)
    events = []
    with output_path.open("w", encoding="utf-8") as output:
        for packet_id, packet in enumerate(read_pcap(input_path), start=1):
            event = parse_packet(packet, packet_id, source)
            processed = decode_event(event, config)
            saved = processed.to_dict()
            output.write(json.dumps(saved, ensure_ascii=False) + "\n")
            events.append(saved)
    return events


def summarize(events: list[dict]) -> list[dict]:
    return [
        {
            "packet_id": event["packet"]["packet_id"],
            "decode_status": event["decode_status"],
            "text": event["decoded"]["payload"]["text"],
            "error_codes": [error["code"] for error in event["errors"]],
        }
        for event in events
    ]


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Reproduce Lab 2 T04 invalid bytes")
    parser.add_argument("--output-dir", type=Path, default=root / "TEST/lab02/T04")
    directory = parser.parse_args().output_dir
    input_path = directory / "input.pcap"
    generate_input_pcap(input_path)
    print(f"Created {input_path} with 2 packets")

    (directory / "expected.json").write_text(
        json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    config = load_config(root / "config/default.toml").decoder
    for policy in ("replace", "strict"):
        output_path = directory / f"actual-{policy}.jsonl"
        events = decode_pcap(
            input_path, output_path, replace(config, invalid_bytes_policy=policy)
        )
        actual = summarize(events)
        if actual != EXPECTED[policy]:
            raise RuntimeError(f"T04 failed for policy {policy}: {actual!r}")
        print(f"{policy}: {len(events)} events -> {output_path}")
        for item in actual:
            print(f"  packet {item['packet_id']}: {item['decode_status']}; text={item['text']!r}")
    print("T04 PASS: invalid bytes recorded; the next packet decoded under both policies")


if __name__ == "__main__":
    main()
