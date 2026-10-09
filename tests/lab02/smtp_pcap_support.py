"""Generate SMTP DATA packets and run PCAP reader/parser/decoder to JSONL."""

import json
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.capture.pcap import read_pcap
from ids.config import DecoderConfig
from ids.decoders.decoder import decode_event
from ids.models import CaptureSource
from ids.pipeline import parse_packet


def write_smtp_pcap(path: Path, payloads: list[bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    start = datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()
    sequence = 1000
    for index, payload in enumerate(payloads):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="10.0.0.1", dst="10.0.0.25")
            / TCP(sport=51000, dport=25, flags="PA", seq=sequence)
            / Raw(payload)
        )
        packet.time = start + index
        sequence += len(payload)
        packets.append(packet)
    wrpcap(str(path), packets)


def decode_smtp_pcap(input_path: Path, output_path: Path, config: DecoderConfig) -> list[dict]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source = CaptureSource("pcap", input_path.name)
    events = []
    with output_path.open("w", encoding="utf-8") as output:
        for packet_id, packet in enumerate(read_pcap(input_path), 1):
            event = decode_event(parse_packet(packet, packet_id, source), config).to_dict()
            output.write(json.dumps(event, ensure_ascii=False) + "\n")
            events.append(event)
    return events
