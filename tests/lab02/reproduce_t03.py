"""Reproduce T03 SMTP/MIME Base64 and Quoted-Printable using a single PCAP."""

import argparse
import base64
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from ids.config import load_config
from tests.lab02.smtp_pcap_support import decode_smtp_pcap, write_smtp_pcap


WIRE_BODIES = [
    b"SGVs\r\nbG8=\r\n",
    base64.b64encode("Xin chào IDS".encode()) + b"\r\n",
    b"Xin ch=C3=A0o\r\njoined=\r\nline_a+b=3D1\r\n",
    b"SGVsbG8!\r\n", b"bad=ZZ=20good\r\n", b"/w==\r\n", b"=FF\r\n",
    b"T0s=\r\n", b"SGVsbG8=\r\n", b"AP+A\r\n", b"SGVsbG8=\r\n",
    b"--boundary\r\nContent-Type: text/plain\r\n\r\nbody\r\n--boundary--\r\n",
    b"", b"SGVsbG8=",
]
ENCODINGS = [
    b"base64", b"BaSe64", b"quoted-printable", b"base64", b"quoted-printable",
    b"base64", b"quoted-printable", b"base64", b"x-uuencode", b"base64", None,
    b"7bit", b"base64", b"base64",
]


def expected_entry(status, encoding, text, decoded_bytes, errors=(), parse_status="ok"):
    return {
        "status": status, "parse_status": parse_status, "encoding": encoding,
        "text": text,
        "body_base64": base64.b64encode(decoded_bytes).decode("ascii") if decoded_bytes is not None else None,
        "error_codes": list(errors),
    }


EXPECTED_REPLACE = [
    expected_entry("ok", "base64", "Hello", b"Hello"),
    expected_entry("ok", "base64", "Xin chào IDS", "Xin chào IDS".encode()),
    expected_entry("ok", "quoted-printable", "Xin chào\r\njoinedline_a+b=1\r\n", "Xin chào\r\njoinedline_a+b=1\r\n".encode()),
    expected_entry("error", "base64", None, None, ["invalid_mime_base64"]),
    expected_entry("partial", "quoted-printable", "bad=ZZ good\r\n", b"bad=ZZ good\r\n", ["invalid_quoted_printable"]),
    expected_entry("partial", "base64", "�", b"\xff", ["invalid_character_sequence"]),
    expected_entry("partial", "quoted-printable", "�\r\n", b"\xff\r\n", ["invalid_character_sequence"]),
    expected_entry("ok", "base64", "OK", b"OK"),
    expected_entry("skipped", "x-uuencode", None, None, ["unsupported_transfer_encoding"]),
    expected_entry("ok", "base64", None, b"\x00\xff\x80"),
    expected_entry("ok", "7bit", "SGVsbG8=\r\n", b"SGVsbG8=\r\n"),
    expected_entry("skipped", "7bit", None, None, ["unsupported_mime_structure"]),
    expected_entry("ok", "base64", "", b""),
    expected_entry("partial", "base64", "Hello", b"Hello", ["incomplete_mime_message"], "partial"),
]
EXPECTED_STRICT = deepcopy(EXPECTED_REPLACE)
for index in (5, 6):
    EXPECTED_STRICT[index].update(status="error", text=None)
EXPECTED = {"replace": EXPECTED_REPLACE, "strict": EXPECTED_STRICT}


def payloads() -> list[bytes]:
    result = []
    for index, (wire_body, encoding) in enumerate(zip(WIRE_BODIES, ENCODINGS, strict=True)):
        content_type = (
            b"application/octet-stream" if index == 9 else
            b'multipart/mixed; boundary="boundary"' if index == 11 else
            b'TEXT/PLAIN;\r\n charset="UTF8"' if index == 1 else
            b"text/plain; charset=utf-8"
        )
        headers = b"X-Trace: t03\r\nFrom: alice@example.test\r\nMIME-Version: 1.0\r\nContent-Type: " + content_type + b"\r\n"
        if encoding is not None:
            headers += b"Content-Transfer-Encoding:" + (b"\r\n " if index == 1 else b" ") + encoding + b"\r\n"
        terminator = b".\r\n" if index != 13 else b""
        result.append(headers + b"\r\n" + wire_body + terminator)
    return result


def summarize(events: list[dict]) -> list[dict]:
    result = []
    for event in events:
        mime = event["decoded"]["mime"]
        result.append({
            "status": event["decode_status"], "parse_status": event["packet"]["parse_status"],
            "encoding": mime["transfer_encoding"], "text": mime["text"],
            "body_base64": mime["body_base64"],
            "error_codes": [error["code"] for error in event["errors"]],
        })
    return result


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Reproduce T03 SMTP/MIME Base64 and QP")
    parser.add_argument("--output-dir", type=Path, default=root / "TEST/lab02/T03")
    directory = parser.parse_args().output_dir
    raw_payloads = payloads()
    write_smtp_pcap(directory / "input.pcap", raw_payloads)
    (directory / "expected.json").write_text(
        json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    config = load_config(root / "config/default.toml").decoder
    for policy in EXPECTED:
        events = decode_smtp_pcap(
            directory / "input.pcap", directory / f"actual-{policy}.jsonl",
            replace(config, invalid_bytes_policy=policy),
        )
        actual = summarize(events)
        if actual != EXPECTED[policy]:
            raise RuntimeError(f"T03 {policy} results do not match expectations: {actual!r}")
        for index, (event, wire_body, payload, summary) in enumerate(
            zip(events, WIRE_BODIES, raw_payloads, actual, strict=True), 1
        ):
            raw_body = event["packet"]["application"]["fields"]["body_base64"]
            if (base64.b64decode(raw_body, validate=True) if raw_body is not None else b"") != wire_body:
                raise RuntimeError(f"T03 {policy} packet {index} changed raw body")
            if base64.b64decode(event["packet"]["payload"]["base64"], validate=True) != payload:
                raise RuntimeError(f"T03 {policy} packet {index} changed raw payload")
            print(f"{policy} packet {index}: {summary['encoding']}; {summary['status']}; text={summary['text']!r}")
        print(f"T03 {policy} PASS: {len(events)} events; raw body/payload unchanged")
    print(f"T03 outputs in {directory}")


if __name__ == "__main__":
    main()
