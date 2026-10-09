import base64
import json

import pytest

from ids.config import DecoderConfig
from ids.decoders.decoder import decode_event
from ids.decoders.text import decode_text
from ids.models import CaptureSource, PacketEvent, PayloadInfo
from ids.processing_models import DecodeStatus


def make_event(payload: bytes) -> PacketEvent:
    return PacketEvent(
        packet_id=1,
        timestamp="2026-10-09T00:00:00Z",
        source=CaptureSource("pcap", "text.pcap"),
        captured_length=len(payload),
        payload=PayloadInfo(
            length=len(payload),
            base64=base64.b64encode(payload).decode("ascii") if payload else None,
            preview=payload[:256].decode("utf-8", errors="replace"),
        ),
    )


@pytest.mark.parametrize("payload, charset, text", [
    (b"Hello IDS", "ASCII", "Hello IDS"),
    ("Xin chào IDS".encode("utf-8"), "UTF8", "Xin chào IDS"),
    (b"", "utf-8", ""),
])
def test_valid_ascii_utf8_and_empty_bytes(payload, charset, text):
    result = decode_text(payload, charset=charset)
    assert result.status == DecodeStatus.OK
    assert result.text == text
    assert result.errors == []


def test_character_decoder_uses_configured_ascii_and_marks_non_ascii_bytes():
    result = decode_text(b"hello\xff", DecoderConfig(default_charset="ascii"))
    assert result.charset == "ascii"
    assert result.text == "hello\ufffd"
    assert result.status == DecodeStatus.PARTIAL
    assert result.errors[0].code == "invalid_character_sequence"


@pytest.mark.parametrize("payload", [b"a\xffb", b"\xc0\xaf", b"\xe2\x82"])
def test_invalid_utf8_is_reported_even_when_replacement_returns_text(payload):
    result = decode_text(payload)
    assert result.status == DecodeStatus.PARTIAL
    assert "\ufffd" in result.text
    assert result.errors[0].stage == "decode"
    assert result.errors[0].code == "invalid_character_sequence"


def test_strict_byte_error_does_not_prevent_next_decode():
    config = DecoderConfig(invalid_bytes_policy="strict")
    results = [decode_text(payload, config) for payload in (b"bad\xff", b"next valid")]
    assert results[0].status == DecodeStatus.ERROR
    assert results[0].text is None
    assert results[1].status == DecodeStatus.OK
    assert results[1].text == "next valid"


@pytest.mark.parametrize("charset", ["utf-16", "unknown-charset", "\x00", 123])
def test_bad_charset_returns_error_without_exception(charset):
    result = decode_text(b"hello", charset=charset)
    assert result.status == DecodeStatus.ERROR
    assert result.errors[0].code == "unsupported_charset"


def test_non_bytes_input_returns_error():
    result = decode_text("hello")
    assert result.status == DecodeStatus.ERROR
    assert result.errors[0].code == "invalid_text_input"


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_input_limit_discards_decode_and_records_reason(policy, status):
    config = DecoderConfig(max_input_bytes=3, limit_policy=policy)
    result = decode_text(b"1234", config)
    assert result.status == status
    assert result.text is None
    assert result.errors[0].code == "input_limit_exceeded"
    assert decode_text(b"123", config).status == DecodeStatus.OK


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_output_limit_accounts_for_utf8_replacement_expansion(policy, status):
    config = DecoderConfig(max_output_bytes=2, limit_policy=policy)
    result = decode_text(b"\xff", config)
    assert result.text is None
    assert result.status == status
    assert [error.code for error in result.errors] == [
        "invalid_character_sequence", "output_limit_exceeded"
    ]
    assert decode_text(b"ok", config).status == DecodeStatus.OK


def test_event_uses_full_raw_bytes_not_lossy_256_byte_preview():
    raw = b"a" * 300 + b"\xff"
    event = make_event(raw)
    original = event.to_dict()
    processed = decode_event(event)
    saved = json.loads(json.dumps(processed.to_dict()))
    assert saved["decode_status"] == "partial"
    assert saved["decoded"]["payload"]["text"] == "a" * 300 + "\ufffd"
    assert len(event.payload.preview) == 256
    assert saved["packet"] == original == event.to_dict()
    assert base64.b64decode(saved["packet"]["payload"]["base64"]) == raw
    assert saved["preprocess_status"] is None
    assert saved["processing_action"] == "skip_tracking"
    assert saved["flow"] is None


def test_empty_packet_payload_is_skipped_without_error():
    result = decode_event(make_event(b""))
    assert result.decode_status == DecodeStatus.SKIPPED
    assert result.errors == []


@pytest.mark.parametrize("raw, code", [
    (None, "missing_raw_payload"),
    ("not base64!", "invalid_payload_base64"),
    ("é", "invalid_payload_base64"),
    (123, "invalid_payload_base64"),
])
def test_bad_raw_payload_is_logged_and_next_event_still_decodes(raw, code):
    bad = make_event(b"payload")
    bad.payload.base64 = raw
    results = [decode_event(event) for event in (bad, make_event(b"good"))]
    assert results[0].decode_status == DecodeStatus.ERROR
    assert results[0].errors[0].code == code
    assert results[0].reason
    assert results[1].decoded["payload"]["text"] == "good"


def test_encoded_payload_limit_is_checked_before_allocating_raw_bytes(monkeypatch):
    event = make_event(b"123456")

    def unexpected_base64_decode(*args, **kwargs):
        pytest.fail("Oversized Base64 must be rejected before decoding")

    monkeypatch.setattr("ids.decoders.decoder.base64.b64decode", unexpected_base64_decode)
    result = decode_event(event, DecoderConfig(max_input_bytes=3))
    assert result.decode_status == DecodeStatus.SKIPPED
    assert result.errors[0].code == "input_limit_exceeded"
    assert result.packet.payload.base64 == event.payload.base64


def test_actual_input_limit_is_checked_when_base64_lengths_are_equal():
    # One byte and three bytes both encode to four Base64 characters.
    result = decode_event(make_event(b"abc"), DecoderConfig(max_input_bytes=1))
    assert result.decode_status == DecodeStatus.SKIPPED
    assert result.errors[0].code == "input_limit_exceeded"
