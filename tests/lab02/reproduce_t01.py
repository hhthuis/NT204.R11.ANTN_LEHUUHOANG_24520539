"""Reproduce T01 URI decoding with raw URI preservation and single decoding."""

import argparse
import json
from pathlib import Path

from ids.config import load_config
from tests.lab02.http_pcap_support import decode_http_pcap, write_http_pcap


TARGETS = [
    b"/search?q=%27%20OR%201%3D1",
    b"/a+b?q=x+y%2Bz",
    b"/caf%C3%A9?q=%2527",
    b"/broken?q=%ZZ",
    b"/next",
]
EXPECTED = [
    {"text": "/search?q=' OR 1=1", "status": "ok", "error_codes": []},
    {"text": "/a+b?q=x+y+z", "status": "ok", "error_codes": []},
    {"text": "/café?q=%27", "status": "ok", "error_codes": []},
    {"text": "/broken?q=%ZZ", "status": "partial", "error_codes": ["invalid_percent_encoding"]},
    {"text": "/next", "status": "ok", "error_codes": []},
]


def payloads() -> list[bytes]:
    return [b"GET " + target + b" HTTP/1.1\r\nHost: example.test\r\n\r\n" for target in TARGETS]


def summarize(events: list[dict]) -> list[dict]:
    return [
        {
            "text": event["decoded"]["http"]["uri"]["text"],
            "status": event["decode_status"],
            "error_codes": [error["code"] for error in event["errors"]],
        }
        for event in events
    ]


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Reproduce Lab 2 T01 URL decoding")
    parser.add_argument("--output-dir", type=Path, default=root / "TEST/lab02/T01")
    directory = parser.parse_args().output_dir
    write_http_pcap(directory / "input.pcap", payloads())
    events = decode_http_pcap(
        directory / "input.pcap", directory / "actual.jsonl",
        load_config(root / "config/default.toml").decoder,
    )
    (directory / "expected.json").write_text(
        json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if summarize(events) != EXPECTED:
        raise RuntimeError("T01 decoded URI/status does not match expected results")
    for target, event in zip(TARGETS, events, strict=True):
        raw = event["packet"]["application"]["fields"]["target"]
        if raw != target.decode("ascii"):
            raise RuntimeError("T01 raw URI was modified")
        print(f"raw={raw!r} -> decoded={event['decoded']['http']['uri']['text']!r}; {event['decode_status']}")
    print(f"T01 PASS: {len(events)} events, raw URIs preserved; outputs in {directory}")


if __name__ == "__main__":
    main()
