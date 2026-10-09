"""Reproduce Lab 2 T02: HTTP text HTML entities, raw preservation and safe errors."""

import argparse
import base64
import gzip
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from ids.config import load_config
from tests.lab02.http_pcap_support import decode_http_pcap, write_http_pcap


BODIES = [
    b"&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
    b"&#60;b&#62; &#x3C;i&#x3E; &amp; &apos;",
    b"&amp;lt;script&amp;gt;",
    "Việt Nam &lt;3 + café".encode("utf-8"),
    b"&#0; &#xD800; &#x110000;",
    b"\xff&lt;bad&gt;",
    b"&lt;next&gt;",
    b'{"value":"&lt;script&gt;"}',
    b"",
    b"&lt;charset&gt;",
    gzip.compress(b"&lt;compressed&gt;", mtime=0),
]
CONTENT_TYPES = [
    b"text/html; charset=utf-8", b"text/plain; charset=ascii", b"text/html",
    b'TeXt/HtMl; charset="UTF8"', b"text/html", b"text/html", b"text/plain",
    b"application/json", b"text/html", b"text/html; charset=iso-8859-1", b"text/html",
]
EXPECTED_REPLACE = [
    {"status": "ok", "text": '<script>alert("x")</script>', "error_codes": []},
    {"status": "ok", "text": "<b> <i> & '", "error_codes": []},
    {"status": "ok", "text": "&lt;script&gt;", "error_codes": []},
    {"status": "ok", "text": "Việt Nam <3 + café", "error_codes": []},
    {"status": "partial", "text": "� � �", "error_codes": ["invalid_html_entity"]},
    {"status": "partial", "text": "�<bad>", "error_codes": ["invalid_character_sequence"]},
    {"status": "ok", "text": "<next>", "error_codes": []},
    {"status": "skipped", "text": None, "error_codes": []},
    {"status": "ok", "text": "", "error_codes": []},
    {"status": "error", "text": None, "error_codes": ["unsupported_charset"]},
    {"status": "skipped", "text": None, "error_codes": ["unsupported_http_body_encoding"]},
]
EXPECTED_STRICT = deepcopy(EXPECTED_REPLACE)
EXPECTED_STRICT[5] = {
    "status": "error", "text": None, "error_codes": ["invalid_character_sequence"],
}
EXPECTED = {"replace": EXPECTED_REPLACE, "strict": EXPECTED_STRICT}


def payloads() -> list[bytes]:
    result = []
    for index, (body, content_type) in enumerate(zip(BODIES, CONTENT_TYPES, strict=True)):
        start = (
            b"POST /submit+entity?q=&lt;x&gt; HTTP/1.1\r\nHost: example.test\r\n"
            if index == 3 else b"HTTP/1.1 200 OK\r\n"
        )
        encoding = b"Content-Encoding: gzip\r\n" if index == 10 else b""
        result.append(
            start + b"Content-Type: " + content_type + b"\r\n" + encoding
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        )
    return result


def summarize(events: list[dict]) -> list[dict]:
    return [
        {
            "status": event["decode_status"],
            "text": event["decoded"]["http"]["html"]["text"]
            if event["decoded"]["http"]["html"] is not None else None,
            "error_codes": [error["code"] for error in event["errors"]],
        }
        for event in events
    ]


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Reproduce Lab 2 T02 HTML entity decoding")
    parser.add_argument("--output-dir", type=Path, default=root / "TEST/lab02/T02")
    directory = parser.parse_args().output_dir
    write_http_pcap(directory / "input.pcap", payloads())
    (directory / "expected.json").write_text(
        json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    config = load_config(root / "config/default.toml").decoder
    for policy in EXPECTED:
        events = decode_http_pcap(
            directory / "input.pcap", directory / f"actual-{policy}.jsonl",
            replace(config, invalid_bytes_policy=policy),
        )
        actual = summarize(events)
        if actual != EXPECTED[policy]:
            raise RuntimeError(f"T02 {policy} results do not match expectations: {actual!r}")
        for index, (event, body, summary) in enumerate(zip(events, BODIES, actual, strict=True), 1):
            raw = event["packet"]["application"]["fields"]["body_base64"]
            if (base64.b64decode(raw, validate=True) if raw is not None else b"") != body:
                raise RuntimeError(f"T02 {policy} packet {index} changed raw body")
            print(f"{policy} packet {index}: {summary['status']}; text={summary['text']!r}")
        raw_uri = events[3]["packet"]["application"]["fields"]["target"]
        if raw_uri != "/submit+entity?q=&lt;x&gt;":
            raise RuntimeError("T02 changed raw URI")
        print(f"T02 {policy} PASS: {len(events)} events; raw body/URI unchanged")
    print(f"T02 outputs in {directory}")


if __name__ == "__main__":
    main()
