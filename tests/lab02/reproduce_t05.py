"""T05: equivalent metadata representations normalize alike, retaining raw events."""

import argparse
import json
from copy import deepcopy
from pathlib import Path

from ids.config import load_config
from ids.models import ApplicationInfo, CaptureSource, NetworkInfo, PacketEvent, TransportInfo
from tests.lab02.event_file_support import process_event_file


def fixtures() -> list[dict]:
    events = []
    for index in range(10):
        variant = index % 2 == 0
        packet = PacketEvent(
            packet_id=index + 1, timestamp="2026-10-09T07:00:00+07:00" if variant else "2026-10-09T00:00:00Z",
            captured_length=54, source=CaptureSource("pcap", "synthetic-parser-event"),
            network=NetworkInfo(" ipv4 " if variant else "IPv4", " 10.0.0.1 " if variant else "10.0.0.1", "10.0.0.2"),
            transport=TransportInfo(" tcp " if variant else "TCP", 51000, 8080, {"flags": ["ack", "psh"] if variant else ["PSH", "ACK"]}),
        )
        if index in (0, 1):
            headers = (
                {"Content-Type": "Text/Plain; charset=UTF8", "X-Token": "AbC", "x-token": "DeF"}
                if variant else {"content-type": "Text/Plain; charset=UTF8", "x-token": ["AbC", "DeF"]}
            )
            packet.application = ApplicationInfo("http" if variant else "HTTP", "request", {
                "method": "get" if variant else "GET", "headers": headers,
                "target": "/Admin%2fA?q=x+y&x=%252f" if variant else "/Admin%2FA?q=x+y&x=%252f",
                "body_length": 0, "body_base64": None, "message_complete": True,
            })
        elif index in (2, 3):
            packet.transport = TransportInfo(" udp " if variant else "UDP", 51000, 53)
            packet.application = ApplicationInfo("dns" if variant else "DNS", "response", {
                "questions": [{"name": "Example.COM." if variant else "example.com", "type": "a" if variant else "A", "class": "in" if variant else "IN"}],
                "answers": [{"name": "WWW.Example.COM." if variant else "www.example.com", "type": "cname" if variant else "CNAME", "data": "Target.Example.COM." if variant else "target.example.com"}],
            })
        elif index in (4, 5):
            packet.transport.dst_port = 25
            packet.application = ApplicationInfo("smtp" if variant else "SMTP", "command", {
                "command": "ehlo" if variant else "EHLO",
                "domain": "Client.Example.COM." if variant else "client.example.com",
            })
        elif index in (6, 7):
            packet.transport.dst_port = 25
            packet.application = ApplicationInfo("smtp" if variant else "SMTP", "command", {
                "commands": [{"command": "mail from" if variant else "MAIL FROM", "mailbox": "Alice@Example.COM." if variant else "Alice@example.com"}],
            })
        elif index == 8:
            packet.timestamp = "not-a-timestamp"
        events.append(packet.to_dict())
    return events


BASE = {
    "timestamp": "2026-10-09T00:00:00.000000Z", "captured_length": 54,
    "network": {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
    "transport": {"protocol": "TCP", "src_port": 51000, "dst_port": 8080, "flags": ["PSH", "ACK"]},
    "application": {"protocol": "UNKNOWN", "kind": None, "fields": {}},
}


def expectations() -> list[dict]:
    http = deepcopy(BASE)
    http["application"] = {"protocol": "HTTP", "kind": "request", "fields": {
        "method": "GET", "headers": {"content-type": ["Text/Plain; charset=UTF8"], "x-token": ["AbC", "DeF"]},
        "uri": {"target": "/Admin%2FA?q=x+y&x=%252f", "path": "/Admin%2FA", "query": "q=x+y&x=%252f", "target_form": "origin"},
    }}
    dns = deepcopy(BASE)
    dns["transport"].update(protocol="UDP", dst_port=53, flags=None)
    dns["application"] = {"protocol": "DNS", "kind": "response", "fields": {
        "questions": [{"name": "example.com", "type": "A", "class": "IN"}],
        "answers": [{"name": "www.example.com", "type": "CNAME", "data": "target.example.com"}],
        "authorities": [], "additionals": [],
    }}
    ehlo = deepcopy(BASE)
    ehlo["transport"]["dst_port"] = 25
    ehlo["application"] = {"protocol": "SMTP", "kind": "command", "fields": {
        "commands": [{"command": "EHLO", "domain": "client.example.com"}],
    }}
    mail = deepcopy(BASE)
    mail["transport"]["dst_port"] = 25
    mail["application"] = {"protocol": "SMTP", "kind": "command", "fields": {
        "commands": [{"command": "MAIL FROM", "mailbox": "Alice@example.com"}],
    }}
    invalid = deepcopy(BASE)
    invalid["timestamp"] = None
    values = [http, http, dns, dns, ehlo, ehlo, mail, mail, invalid, BASE]
    return [
        {
            "status": "invalid" if index == 8 else "valid", "normalized": deepcopy(value),
            "error_codes": ["validation_invalid_timestamp", "normalization_invalid_timestamp", "policy_invalid_skip"] if index == 8 else [],
        }
        for index, value in enumerate(values)
    ]


EXPECTED = expectations()


def write_input(path: Path) -> list[dict]:
    path.parent.mkdir(parents=True, exist_ok=True)
    values = fixtures()
    path.write_text("".join(json.dumps(value, ensure_ascii=False) + "\n" for value in values), encoding="utf-8")
    return values


def summarize(events: list[dict]) -> list[dict]:
    return [{"status": event["preprocess_status"], "normalized": event["normalized"], "error_codes": [error["code"] for error in event["errors"]]} for event in events]


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Reproduce T05 event normalization")
    parser.add_argument("--output-dir", type=Path, default=root / "TEST/lab02/T05")
    directory = parser.parse_args().output_dir
    raw = write_input(directory / "input.jsonl")
    events = process_event_file(directory / "input.jsonl", directory / "actual.jsonl", load_config(root / "config/default.toml"))
    (directory / "expected.json").write_text(json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if summarize(events) != EXPECTED:
        raise RuntimeError("T05 normalized output does not match expected results")
    if [event["packet"] for event in events] != raw:
        raise RuntimeError("T05 changed raw event data")
    for first in (0, 2, 4, 6):
        if events[first]["normalized"] != events[first + 1]["normalized"]:
            raise RuntimeError(f"T05 equivalent event pair {first + 1}/{first + 2} normalized differently")
        print(f"events {first + 1}/{first + 2}: same normalized output; raw variants retained")
    print("event 9: invalid timestamp marked; event 10: valid, processing continues")
    print(f"T05 PASS: {len(events)} events; outputs in {directory}")


if __name__ == "__main__":
    main()
