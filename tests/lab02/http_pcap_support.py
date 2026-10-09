"""Shared PCAP-to-decoder helpers for HTTP lab evidence."""

import json
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.capture.pcap import read_pcap
from ids.config import DecoderConfig
from ids.decoders.decoder import decode_event
from ids.models import CaptureSource
from ids.pipeline import parse_packet


def write_http_pcap(path: Path, payloads: list[bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    sequence = 1000
    start = datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()
    for index, payload in enumerate(payloads):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000, dport=8080, flags="PA", seq=sequence)
            / Raw(payload)
        )
        packet.time = start + index
        packets.append(packet)
        sequence += len(payload)
    wrpcap(str(path), packets)


def decode_http_pcap(
    input_path: Path, output_path: Path, config: DecoderConfig
) -> list[dict]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source = CaptureSource("pcap", input_path.name)
    events = []
    with output_path.open("w", encoding="utf-8") as output:
        for packet_id, packet in enumerate(read_pcap(input_path), 1):
            event = decode_event(parse_packet(packet, packet_id, source), config)
            saved = event.to_dict()
            output.write(json.dumps(saved, ensure_ascii=False) + "\n")
            events.append(saved)
    return events
