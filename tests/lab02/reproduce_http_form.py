"""Supplemental evidence for required application/x-www-form-urlencoded decode."""

import argparse
import json
from pathlib import Path

from ids.config import load_config
from tests.lab02.http_pcap_support import decode_http_pcap, write_http_pcap


BODIES = [
    b"tag=one&tag=two&name=Alice+Bob&plus=%2B&data=a%26b%3Dc&blank=",
    b"caf%C3%A9=Vi%E1%BB%87t+Nam&once=%252B",
    b"q=%ZZ",
    b"q=\xff",
    b"q=next",
    b"q=a+b",
    b"",
]
CONTENT_TYPES = [
    b"application/x-www-form-urlencoded",
    b'Application/X-WWW-Form-Urlencoded; charset="UTF8"',
    b"application/x-www-form-urlencoded",
    b"application/x-www-form-urlencoded",
    b"application/x-www-form-urlencoded",
    b"text/plain",
    b"application/x-www-form-urlencoded",
]
EXPECTED = [
    {
        "status": "ok",
        "parameters": {
            "tag": ["one", "two"], "name": ["Alice Bob"], "plus": ["+"],
            "data": ["a&b=c"], "blank": [""],
        },
        "error_codes": [],
    },
    {"status": "ok", "parameters": {"café": ["Việt Nam"], "once": ["%2B"]}, "error_codes": []},
    {"status": "partial", "parameters": {"q": ["%ZZ"]}, "error_codes": ["invalid_percent_encoding"]},
    {"status": "partial", "parameters": {"q": ["�"]}, "error_codes": ["invalid_character_sequence"]},
    {"status": "ok", "parameters": {"q": ["next"]}, "error_codes": []},
    {"status": "ok", "parameters": None, "error_codes": []},
    {"status": "ok", "parameters": {}, "error_codes": []},
]


def payloads() -> list[bytes]:
    return [
        b"POST /submit HTTP/1.1\r\nHost: example.test\r\nContent-Type: "
        + content_type
        + f"\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
        for body, content_type in zip(BODIES, CONTENT_TYPES, strict=True)
    ]


def summarize(events: list[dict]) -> list[dict]:
    result = []
    for event in events:
        form = event["decoded"]["http"]["form"]
        result.append({
            "status": event["decode_status"],
            "parameters": form["parameters"] if form is not None else None,
            "error_codes": [error["code"] for error in event["errors"]],
        })
    return result


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Reproduce HTTP form decoding")
    parser.add_argument("--output-dir", type=Path, default=root / "TEST/lab02/http-form")
    directory = parser.parse_args().output_dir
    write_http_pcap(directory / "input.pcap", payloads())
    events = decode_http_pcap(
        directory / "input.pcap", directory / "actual.jsonl",
        load_config(root / "config/default.toml").decoder,
    )
    (directory / "expected.json").write_text(
        json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    actual = summarize(events)
    if actual != EXPECTED:
        raise RuntimeError(f"HTTP form results do not match expectations: {actual!r}")
    for index, summary in enumerate(actual, 1):
        print(f"packet {index}: {summary['status']}; parameters={summary['parameters']!r}")
    print(f"HTTP form PASS: {len(events)} events; outputs in {directory}")


if __name__ == "__main__":
    main()
