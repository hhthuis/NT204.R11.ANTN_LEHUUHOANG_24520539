import base64
import json

import pytest
from scapy.all import Ether, IP, Raw, TCP

from ids.config import DecoderConfig
from ids.decoders.decoder import decode_event
from ids.decoders.mime import decode_mime_body
from ids.models import CaptureSource
from ids.parsers.application.detector import detect_application_protocol
from ids.parsers.application.mime import parse_mime
from ids.parsers.application.smtp import parse_smtp
from ids.pipeline import parse_packet


def make_mime_event(body=b"SGVsbG8=", encoding=b"base64", content_type=b"text/plain; charset=utf-8"):
    payload = (
        b"From: alice@example.test\r\nMIME-Version: 1.0\r\nContent-Type: " + content_type
        + b"\r\nContent-Transfer-Encoding: " + encoding + b"\r\n\r\n" + body
        + b"\r\n.\r\n"
    )
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.25")
        / TCP(sport=51000, dport=25, flags="PA") / Raw(payload)
    )
    return parse_packet(packet, 1, CaptureSource("pcap", "mime.pcap"))


@pytest.mark.parametrize("body, encoding, expected", [
    (b"SGVsbG8=", "base64", "Hello"),
    (b"SGVs\r\nbG8=\r\n \t", " BaSe64 ", "Hello"),
    (base64.b64encode("Xin chào".encode()), "base64", "Xin chào"),
    (b"Xin ch=C3=A0o", "quoted-printable", "Xin chào"),
    (b"a=3Db=0D=0Ac", "quoted-printable", "a=b\r\nc"),
    (b"long=\r\nline=\nnext", "quoted-printable", "longlinenext"),
    (b"a_b+c=2B=5F", "quoted-printable", "a_b+c+_"),
    (b"=3d=3D", "quoted-printable", "=="),
    (b"=253Cscript=253E", "quoted-printable", "%3Cscript%3E"),
    (base64.b64encode(b"SGVsbG8="), "base64", "SGVsbG8="),
    (b"SGVsbG8=", None, "SGVsbG8="),
    (b"raw text", "7bit", "raw text"),
    ("café".encode(), "8bit", "café"),
    (b"text", "binary", "text"),
    (b"", "base64", ""),
    (b"", "quoted-printable", ""),
])
def test_transfer_decoding_is_header_directed_and_one_pass(body, encoding, expected):
    result = decode_mime_body(body, encoding)
    assert result.status == "ok"
    assert result.text == expected
    assert base64.b64decode(result.body_base64) == expected.encode()
    assert result.body_length == len(expected.encode())
    assert result.errors == []


@pytest.mark.parametrize("body", [b"!SGVsbG8=", b"SGVsbG8", b"a===", b"SGVsbG8=AAAA", b"AAAA====", b"AB==", b"SGVsbG8=\xff"])
def test_invalid_base64_is_not_silently_accepted(body):
    result = decode_mime_body(body, "base64")
    assert result.status == "error"
    assert result.text is None and result.body_base64 is None
    assert result.errors[0].code == "invalid_mime_base64"


@pytest.mark.parametrize("body, expected", [
    (b"bad=ZZ=20good", "bad=ZZ good"), (b"bad=", "bad="),
    (b"a=1", "a=1"), (b"a=\rX", "a=\rX"),
])
def test_invalid_qp_escape_is_preserved_and_marked_partial(body, expected):
    result = decode_mime_body(body, "quoted-printable")
    assert result.text == expected
    assert result.status == "partial"
    assert [error.code for error in result.errors] == ["invalid_quoted_printable"]


def test_qp_trailing_transport_space_is_removed_but_encoded_space_is_kept():
    result = decode_mime_body(b"a \t\r\nb=20\r\n", "quoted-printable")
    assert result.text == "a\r\nb \r\n"


@pytest.mark.parametrize("encoding, encoded", [("base64", b"/w=="), ("quoted-printable", b"=FF")])
@pytest.mark.parametrize("policy, status, text", [("replace", "partial", "�"), ("strict", "error", None)])
def test_invalid_decoded_character_bytes_follow_policy(encoding, encoded, policy, status, text):
    result = decode_mime_body(encoded, encoding, DecoderConfig(invalid_bytes_policy=policy))
    assert result.status == status and result.text == text
    assert result.errors[0].code == "invalid_character_sequence"
    assert base64.b64decode(result.body_base64) == b"\xff"
    assert decode_mime_body(b"T0s=", "base64").text == "OK"


def test_binary_content_retains_exact_decoded_bytes_without_utf8_errors():
    result = decode_mime_body(b"AP+A", "base64", content_type="application/octet-stream")
    assert result.status == "ok" and result.text is None and result.charset is None
    assert base64.b64decode(result.body_base64) == b"\x00\xff\x80"
    assert result.body_length == 3


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_raw_input_limit_precedes_transfer_decode(policy, status, monkeypatch):
    def unexpected_call(*args, **kwargs):
        pytest.fail("oversized input must not be transfer-decoded")
    monkeypatch.setattr("ids.decoders.mime.base64.b64decode", unexpected_call)
    result = decode_mime_body(b"SGVsbG8=", "base64", DecoderConfig(max_input_bytes=7, limit_policy=policy))
    assert result.status == status and result.body_base64 is None
    assert result.errors[0].code == "input_limit_exceeded"


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_output_limits_decoded_bytes_and_replacement_text(policy, status):
    config = DecoderConfig(max_output_bytes=4, limit_policy=policy)
    result = decode_mime_body(b"SGVsbG8=", "base64", config)
    assert result.status == status and result.body_base64 is None
    assert result.errors[0].code == "output_limit_exceeded"
    assert decode_mime_body(b"SGVsbG8=", "base64", DecoderConfig(max_output_bytes=5)).text == "Hello"
    result = decode_mime_body(b"/w==", "base64", DecoderConfig(max_output_bytes=2, limit_policy=policy))
    assert result.status == status and result.body_base64 is None
    assert [error.code for error in result.errors] == ["invalid_character_sequence", "output_limit_exceeded"]


@pytest.mark.parametrize("body, encoding, content_type, code", [
    ("SGVsbG8=", "base64", "text/plain", "invalid_mime_body"),
    (b"abc", 123, "text/plain", "invalid_transfer_encoding"),
    (b"abc", "base64", None, "invalid_mime_content_type"),
])
def test_invalid_input_types_return_safe_errors(body, encoding, content_type, code):
    result = decode_mime_body(body, encoding, content_type=content_type)
    assert result.status == "error" and result.errors[0].code == code


@pytest.mark.parametrize("encoding, content_type, code", [
    ("x-uuencode", "text/plain", "unsupported_transfer_encoding"),
    ("base64", "multipart/mixed", "unsupported_mime_structure"),
    ("base64", "message/rfc822", "unsupported_mime_structure"),
])
def test_unsupported_encoding_or_structure_is_skipped_with_reason(encoding, content_type, code):
    result = decode_mime_body(b"SGVsbG8=", encoding, content_type=content_type)
    assert result.status == "skipped" and result.text is None
    assert result.errors[0].code == code


def test_mime_adapter_and_event_preserve_headers_wire_body_and_payload():
    event = make_mime_event(b"Xin ch=C3=A0o", b"Quoted-Printable")
    original = event.to_dict()
    result = decode_event(event)
    saved = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))
    assert saved["packet"] == original == event.to_dict()
    assert event.application.kind == "message" and event.parse_status == "ok"
    mime = saved["decoded"]["mime"]
    assert mime["text"] == "Xin chào\r\n"
    assert mime["transfer_encoding"] == "quoted-printable" and mime["status"] == "ok"
    assert base64.b64decode(event.application.fields["body_base64"]) == b"Xin ch=C3=A0o\r\n"
    assert b"Content-Transfer-Encoding: Quoted-Printable" in base64.b64decode(event.application.fields["headers_base64"])
    assert result.preprocess_status is None and result.flow is None


def test_smtp_dot_unstuffing_is_separate_from_raw_body():
    event = make_mime_event(b"..first\r\n...second", b"8bit")
    result = decode_event(event)
    assert result.decoded["mime"]["text"] == ".first\r\n..second\r\n"
    assert base64.b64decode(result.packet.application.fields["body_base64"]) == b"..first\r\n...second\r\n"
    standalone = parse_mime(b"Content-Type: text/plain\r\n\r\n..literal\r\n.\r\n")
    event.application = standalone.application
    assert decode_event(event).decoded["mime"]["text"] == "..literal\r\n.\r\n"


def test_charset_header_has_priority_over_config_and_unsupported_is_reported():
    event = make_mime_event(base64.b64encode("café".encode()))
    assert decode_event(event, DecoderConfig(default_charset="ascii")).decoded["mime"]["text"] == "café"
    event.application.fields["headers"]["content-type"] = ['text/plain; charset="latin-1"']
    result = decode_event(event)
    assert result.decode_status == "error" and result.errors[0].code == "unsupported_charset"
    assert result.reason


@pytest.mark.parametrize("raw, code", [(None, "missing_raw_mime_body"), (123, "invalid_mime_body_base64"), ("!", "invalid_mime_body_base64")])
def test_bad_stored_raw_body_reports_error_and_next_message_continues(raw, code):
    event = make_mime_event()
    event.application.fields["body_base64"] = raw
    result = decode_event(event)
    assert result.decode_status == "error" and result.reason
    assert result.errors[0].code == code
    assert decode_event(make_mime_event()).decoded["mime"]["text"] == "Hello"


def test_stored_base64_limit_is_checked_before_allocation(monkeypatch):
    event = make_mime_event(b"A" * 100)
    def unexpected_call(*args, **kwargs):
        pytest.fail("oversized storage Base64 must not allocate raw bytes")
    monkeypatch.setattr("ids.decoders.mime.base64.b64decode", unexpected_call)
    result = decode_event(event, DecoderConfig(max_input_bytes=40))
    assert result.decode_status == "skipped" and result.reason
    assert result.errors[0].code == "input_limit_exceeded"


def test_actual_wire_body_limit_when_base64_storage_length_matches_boundary():
    event = make_mime_event()
    event.application.fields["headers"] = {}
    event.application.fields["body_base64"] = "YWJj"
    result = decode_event(event, DecoderConfig(max_input_bytes=1))
    assert result.decode_status == "skipped"
    assert result.errors[0].code == "input_limit_exceeded"


@pytest.mark.parametrize("headers, code", [
    (None, "invalid_mime_fields"),
    ({"content-transfer-encoding": ["base64", "base64"]}, "ambiguous_mime_header"),
    ({"Content-Type": "text/plain", "content-type": "text/html"}, "ambiguous_mime_header"),
    ({"content-type": 123}, "invalid_mime_header"),
])
def test_malformed_or_ambiguous_headers_are_safe(headers, code):
    event = make_mime_event()
    event.application.fields["headers"] = headers
    result = decode_event(event)
    assert result.decode_status == "error" and result.errors[0].code == code


def test_header_input_limit_and_empty_body():
    event = make_mime_event()
    event.application.fields["headers"]["content-type"] = ["text/plain; charset=" + "a" * 100]
    assert decode_event(event, DecoderConfig(max_input_bytes=40)).errors[0].code == "input_limit_exceeded"
    event.application = parse_mime(b"Content-Transfer-Encoding: base64\r\n\r\n").application
    result = decode_event(event)
    assert result.decode_status == "ok"
    assert result.decoded["mime"]["text"] == "" and result.decoded["mime"]["body_base64"] == ""


def test_existing_smtp_command_response_character_decoding_remains_available():
    event = make_mime_event()
    for payload in (b"EHLO example.test\r\n", b"250 OK\r\n"):
        event.application = parse_smtp(payload).application
        event.payload.base64 = base64.b64encode(payload).decode()
        assert decode_event(event).decoded["payload"]["text"] == payload.decode()


def test_folded_duplicate_noncritical_headers_are_preserved():
    result = parse_mime(
        b"Subject: first\r\n\tsecond\r\nX-Tag: one\r\nX-Tag: two\r\n"
        b"CONTENT-TRANSFER-ENCODING:\r\n base64\r\n\r\nSGVsbG8="
    )
    assert result.complete
    assert result.application.fields["headers"]["subject"] == ["first second"]
    assert result.application.fields["headers"]["x-tag"] == ["one", "two"]
    event = make_mime_event()
    event.application = result.application
    assert decode_event(event).decoded["mime"]["text"] == "Hello"


@pytest.mark.parametrize("payload", [
    b"Content-Type: text/plain\r\n",
    b"Content-Type: text/plain\r\nmalformed\r\n\r\nhello\r\n.\r\n",
    b"Content-Type: text/plain\r\n\r\nhello",
])
def test_incomplete_mime_has_safe_status_and_reason(payload):
    event = make_mime_event()
    result = parse_smtp(payload)
    assert not result.complete and result.warnings
    event.application = result.application
    processed = decode_event(event)
    assert processed.decode_status in ("partial", "error") and processed.reason


def test_data_prefix_and_bytes_after_terminator_are_preserved_and_marked_partial():
    payload = b"DATA\r\nContent-Type: text/plain\r\n\r\nhello\r\n.\r\nQUIT\r\n"
    result = parse_smtp(payload)
    assert result.application.kind == "message" and not result.complete
    assert result.application.fields["remaining_bytes"] == len(b"QUIT\r\n")
    assert base64.b64decode(result.application.fields["body_base64"]) == b"hello\r\n"


def test_mime_detection_requires_smtp_port_and_does_not_override_other_protocols():
    payload = b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n.\r\n"
    assert detect_application_protocol(payload, "TCP", 51000, 25) == "SMTP"
    assert detect_application_protocol(payload, "TCP", 51000, 9000) == "UNKNOWN"
    assert detect_application_protocol(payload, "UDP", 51000, 25) == "UNKNOWN"
    assert detect_application_protocol(b"X-Trace: abc\r\n" + payload, "TCP", 51000, 25) == "SMTP"
    assert detect_application_protocol(b"X-Trace: abc\r\n\r\n" + payload, "TCP", 51000, 25) == "UNKNOWN"
    event = make_mime_event()
    assert event.application.kind == "message"
