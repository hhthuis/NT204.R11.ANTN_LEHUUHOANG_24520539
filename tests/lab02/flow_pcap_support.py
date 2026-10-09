"""Synthetic transport PCAP → Parser → Decoder → Preprocessor → FlowTracker."""

import json
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap

from ids.capture.pcap import read_pcap
from ids.config import ProcessingConfig
from ids.decoders.decoder import decode_event
from ids.flows.tracker import FlowTracker
from ids.models import CaptureSource
from ids.pipeline import parse_packet
from ids.preprocessors.preprocessor import preprocess_event


def write_transport_pcap(path: Path, scenarios: list[tuple[str, str, int, str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    start = datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()
    for index, (protocol, src, sport, dst, dport) in enumerate(scenarios):
        if protocol == "TCP":
            layer = TCP(sport=sport, dport=dport, flags="A", seq=1000 + index)
        elif protocol == "UDP":
            layer = UDP(sport=sport, dport=dport)
        elif protocol == "ICMP":
            layer = ICMP()
        else:
            raise ValueError("Synthetic fixture supports TCP, UDP and ICMP only")
        packet = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src=src, dst=dst) / layer
        packet.time = start + index
        packets.append(packet)
    wrpcap(str(path), packets)


def track_pcap(input_path: Path, output_path: Path, flows_path: Path, config: ProcessingConfig) -> tuple[list[dict], list[dict]]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    flows_path.parent.mkdir(parents=True, exist_ok=True)
    tracker = FlowTracker()
    source = CaptureSource("pcap", input_path.name)
    events = []
    with output_path.open("w", encoding="utf-8") as output:
        for packet_id, packet in enumerate(read_pcap(input_path), 1):
            parsed = parse_packet(packet, packet_id, source)
            prepared = preprocess_event(decode_event(parsed, config.decoder), config.preprocessor)
            before = prepared.to_dict()
            saved = tracker.track(prepared).to_dict()
            for name in ("packet", "decoded", "normalized", "decode_status", "preprocess_status", "processing_action", "errors", "reason"):
                if saved[name] != before[name]:
                    raise AssertionError(f"Tracker changed {name} for packet {packet_id}")
            if prepared.to_dict() != before:
                raise AssertionError("Tracker mutated its caller's event")
            output.write(json.dumps(saved, ensure_ascii=False) + "\n")
            events.append(saved)
    flows = tracker.export_flows()
    flows_path.write_text(json.dumps(flows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return events, flows


def summarize(events: list[dict]) -> list[dict]:
    return [{"packet_id": event["packet"]["packet_id"], "action": event["processing_action"],
             "status": event["preprocess_status"], "flow": event["flow"]} for event in events]
