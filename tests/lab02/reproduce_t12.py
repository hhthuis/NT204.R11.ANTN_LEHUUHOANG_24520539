"""T12: explicit no-packet maintenance, TCP/UDP expiry and a new lifetime."""

import argparse
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, wrpcap

from ids.capture.pcap import read_pcap
from ids.config import load_config
from ids.decoders.decoder import decode_event
from ids.flows.tracker import FlowTracker
from ids.models import CaptureSource
from ids.pipeline import parse_packet
from ids.preprocessors.preprocessor import preprocess_event


TCP_ID = "flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2"
UDP_ID = "flow-49eea37761fea07cb47284081a58798c70134ddc017ab8c4eb2ab5b048217879"
NEW_UDP_ID = "flow-d30fae60294ab61ff79b180a7873bbab9c22f6a0ef472821020a2b5e054b9d2f"
BASE = datetime(2026, 10, 9, tzinfo=timezone.utc)
CONFIG = "[tracker]\ntcp_idle_timeout=3\nudp_idle_timeout=2\nexpiry_check_interval=0.1\nmax_active_flows=10\nmax_pending_summaries=2\n"


def expected_summary(identifier, protocol, start, last, end, packets, size, duration):
    return {
        "flow_id": identifier, "protocol": protocol, "application_protocol": "UNKNOWN",
        "endpoint_a": {"ip": "10.0.0.2", "port": 51000}, "endpoint_b": {"ip": "10.0.0.1", "port": 8080},
        "start_time": start, "last_seen": last, "duration": duration,
        "packet_count": packets, "byte_count": size,
        "forward_packet_count": packets, "forward_byte_count": size, "backward_packet_count": 0, "backward_byte_count": 0,
        "syn_count": 0, "ack_count": packets if protocol == "TCP" else 0, "fin_count": 0, "rst_count": 0,
        "state": "CLOSED" if protocol == "TCP" else None, "observed_state": "NEW" if protocol == "TCP" else None,
        "schema_version": "1.0", "end_reason": "idle_timeout", "end_time": end,
    }


EXPECTED = {
    "associations": [TCP_ID, UDP_ID, TCP_ID, NEW_UDP_ID],
    "active_counts": [2, 1, 0, 1, 0],
    "summaries": [
        expected_summary(UDP_ID, "UDP", "2026-10-09T00:00:00.000000Z", "2026-10-09T00:00:00.000000Z", "2026-10-09T00:00:02.000000Z", 1, 42, 0.0),
        expected_summary(TCP_ID, "TCP", "2026-10-09T00:00:00.000000Z", "2026-10-09T00:00:01.000000Z", "2026-10-09T00:00:04.000000Z", 2, 108, 1.0),
        expected_summary(NEW_UDP_ID, "UDP", "2026-10-09T00:00:04.100000Z", "2026-10-09T00:00:04.100000Z", "2026-10-09T00:00:06.100000Z", 1, 42, 0.0),
    ],
}


def generate_input_pcap(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    for protocol, offset in [("TCP", "0"), ("UDP", "0"), ("TCP", "1"), ("UDP", "4.1")]:
        layer = TCP(sport=51000, dport=8080, flags="A") if protocol == "TCP" else UDP(sport=51000, dport=8080)
        packet = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src="10.0.0.2", dst="10.0.0.1") / layer
        packet.time = Decimal(str(BASE.timestamp())) + Decimal(offset)
        packets.append(packet)
    wrpcap(str(path), packets)


def reproduce(directory):
    directory.mkdir(parents=True, exist_ok=True)
    generate_input_pcap(directory / "input.pcap")
    (directory / "config.toml").write_text(CONFIG)
    (directory / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n")
    tracker = FlowTracker(load_config(directory / "config.toml").tracker)
    events, summaries, counts = [], [], []

    def drain():
        while tracker.pending_count:
            summary = tracker.pending_summary()
            summaries.append(summary)
            tracker.acknowledge_summary(summary["flow_id"])

    for index, packet in enumerate(read_pcap(directory / "input.pcap"), 1):
        if index == 4:
            counts.append(tracker.active_count)
            for seconds in (2, 4):
                assert tracker.expire(BASE + timedelta(seconds=seconds)) == 1
                drain()
                counts.append(tracker.active_count)
        event = preprocess_event(decode_event(parse_packet(packet, index, CaptureSource("pcap", "input.pcap"))))
        events.append(tracker.track(event).to_dict())
    counts.append(tracker.active_count)
    assert tracker.expire(BASE + timedelta(seconds=6.1)) == 1
    drain()
    counts.append(tracker.active_count)
    actual = {"associations": [event["flow"]["flow_id"] for event in events], "active_counts": counts, "summaries": summaries}
    if actual != EXPECTED:
        raise AssertionError("T12 expiry, cleanup, statistics or new generation mismatch")
    assert not tracker._tcp_handshakes and not tracker._tcp_closes and tracker.pending_count == 0
    for name, rows in (("actual.jsonl", events), ("flows.jsonl", summaries)):
        (directory / name).write_text("".join(json.dumps(row) + "\n" for row in rows))
    (directory / "checkpoints.json").write_text(json.dumps(actual, indent=2) + "\n")
    return events, summaries


def main():
    parser = argparse.ArgumentParser(description="Reproduce T12 TCP/UDP idle timeout")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T12")
    reproduce(parser.parse_args().output_dir)
    print("T12 PASS: TCP/UDP idle expiry without packets; active counts 2→1→0→1→0; 3 summaries, fresh UDP generation")


if __name__ == "__main__":
    main()
