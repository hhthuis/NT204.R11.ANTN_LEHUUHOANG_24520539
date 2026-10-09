import base64
import json

import pytest
from scapy.all import Ether, IP, Raw, TCP

from ids.config import DecoderConfig
from ids.decoders.decoder import decode_event
from ids.decoders.http import decode_form, decode_uri
from ids.models import ApplicationInfo, CaptureSource, PacketEvent
from ids.pipeline import parse_packet


def make_http_event(
    target=b"/", body=b"", content_type=None, content_length=None
):
    payload = b"POST " + target + b" HTTP/1.1\r\nHost: example.test\r\n"
    if content_type is not None:
        payload += b"Content-Type: " + content_type + b"\r\n"
    length = len(body) if content_length is None else content_length
    payload += f"Content-Length: {length}\r\n\r\n".encode("ascii") + body
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=8080, flags="PA")
        / Raw(payload)
    )
    return parse_packet(packet, 1, CaptureSource("pcap", "http.pcap"))


@pytest.mark.parametrize("raw, expected", [
    ("%27%20OR%201%3D1", "' OR 1=1"),
    ("/search?q=%27%20OR%201%3D1", "/search?q=' OR 1=1"),
    ("/a+b?q=x+y%2Bz", "/a+b?q=x+y+z"),
    ("/caf%C3%A9", "/café"),
    ("/café", "/café"),
    ("/%2527", "/%27"),
    ("/%2f%2F", "///"),
])
def test_uri_percent_decoding_is_one_pass_and_preserves_literal_plus(raw, expected):
    result = decode_uri(raw)
    assert result.text == expected
    assert result.status == "ok"
    assert result.errors == []


@pytest.mark.parametrize("raw", ["/%", "/%2", "/%XZ"])
def test_invalid_percent_escape_is_preserved_and_reported(raw):
    result = decode_uri(raw)
    assert result.text == raw
    assert result.status == "partial"
    assert result.errors[0].code == "invalid_percent_encoding"


@pytest.mark.parametrize("policy, status, text", [
    ("replace", "partial", "/�"),
    ("strict", "error", None),
])
def test_percent_decoded_invalid_utf8_uses_byte_policy(policy, status, text):
    result = decode_uri("/%FF", DecoderConfig(invalid_bytes_policy=policy))
    assert result.status == status
    assert result.text == text
    assert result.errors[0].code == "invalid_character_sequence"


@pytest.mark.parametrize("raw", [None, 123, "/\ud800"])
def test_invalid_uri_input_returns_error(raw):
    assert decode_uri(raw).status == "error"


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_uri_limits_original_input_before_percent_reduction(policy, status):
    result = decode_uri("%41", DecoderConfig(max_input_bytes=2, limit_policy=policy))
    assert result.status == status
    assert result.text is None
    assert result.errors[0].code == "input_limit_exceeded"


def test_uri_input_limit_counts_utf8_bytes_not_python_character_count():
    result = decode_uri("é", DecoderConfig(max_input_bytes=1))
    assert result.status == "skipped"
    assert result.errors[0].code == "input_limit_exceeded"


def test_uri_output_limit_counts_replacement_expansion():
    result = decode_uri("%FF", DecoderConfig(max_output_bytes=2))
    assert result.status == "skipped"
    assert result.text is None
    assert result.errors[0].code == "invalid_character_sequence"
    assert result.errors[1].code == "output_limit_exceeded"


def test_form_preserves_repeats_blanks_and_encoded_delimiters():
    raw = b"tag=one&tag=two&name=Alice+Bob&plus=%2B&data=a%26b%3Dc&blank=&flag&=value&&"
    result = decode_form(raw)
    assert result.status == "ok"
    assert result.parameters == {
        "tag": ["one", "two"], "name": ["Alice Bob"], "plus": ["+"],
        "data": ["a&b=c"], "blank": [""], "flag": [""], "": ["value"],
    }


def test_form_percent_encoded_names_merge_and_decode_only_once():
    result = decode_form(b"t%61g=one&tag=%252B")
    assert result.parameters == {"tag": ["one", "%2B"]}


def test_form_utf8_names_and_values():
    result = decode_form(b"caf%C3%A9=Vi%E1%BB%87t+Nam")
    assert result.parameters == {"café": ["Việt Nam"]}


def test_empty_form_is_valid_empty_mapping():
    result = decode_form(b"")
    assert result.status == "ok"
    assert result.parameters == {}
    assert result.charset == "utf-8"


def test_form_invalid_escapes_are_preserved_with_bounded_error_reporting():
    result = decode_form(b"q=%ZZ&q=%XY")
    assert result.parameters == {"q": ["%ZZ", "%XY"]}
    assert result.status == "partial"
    assert [error.code for error in result.errors] == ["invalid_percent_encoding"]


@pytest.mark.parametrize("policy, status, parameters", [
    ("replace", "partial", {"q": ["�"]}),
    ("strict", "error", None),
])
def test_form_invalid_decoded_utf8_uses_policy(policy, status, parameters):
    result = decode_form(b"q=%FF", DecoderConfig(invalid_bytes_policy=policy))
    assert result.status == status
    assert result.parameters == parameters


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_form_limits_total_decoded_fields_not_only_each_value(policy, status):
    result = decode_form(b"a=1&b=2", DecoderConfig(max_output_bytes=3, limit_policy=policy))
    assert result.status == status
    assert result.parameters is None
    assert result.errors[-1].code == "output_limit_exceeded"
    assert decode_form(b"a=1&b=2", DecoderConfig(max_output_bytes=4)).status == "ok"


def test_form_input_limit_applies_before_splitting():
    result = decode_form(b"q=%41", DecoderConfig(max_input_bytes=4))
    assert result.status == "skipped"
    assert result.errors[0].code == "input_limit_exceeded"


def test_form_requires_bytes_and_reports_unsupported_charset():
    assert decode_form("q=value").status == "error"
    assert decode_form(b"", charset="utf-16").status == "error"


def test_http_adapter_preserves_raw_uri_body_and_payload_after_json_round_trip():
    body = b"tag=one&tag=two&name=Alice+Bob"
    event = make_http_event(b"/a+b?q=%27%20OR%201%3D1", body, b"application/x-www-form-urlencoded")
    original = event.to_dict()
    saved = json.loads(json.dumps(decode_event(event).to_dict(), ensure_ascii=False))
    assert saved["decoded"]["http"]["uri"]["text"] == "/a+b?q=' OR 1=1"
    assert saved["decoded"]["http"]["form"]["parameters"] == {
        "tag": ["one", "two"], "name": ["Alice Bob"]
    }
    assert saved["decode_status"] == "ok"
    assert saved["packet"] == original == event.to_dict()
    assert base64.b64decode(saved["packet"]["application"]["fields"]["body_base64"]) == body


def test_http_adapter_recovers_unescaped_utf8_uri_bytes_from_latin1_parser_target():
    event = make_http_event("/café".encode("utf-8"))
    assert event.application.fields["target"] == "/cafÃ©"
    assert decode_event(event).decoded["http"]["uri"]["text"] == "/café"


def test_form_content_type_is_case_insensitive_and_honors_quoted_charset():
    event = make_http_event(
        body=b"q=caf%C3%A9",
        content_type=b'Application/X-WWW-Form-Urlencoded; CHARSET="UTF8"',
    )
    result = decode_event(event, DecoderConfig(default_charset="ascii"))
    assert result.decoded["http"]["form"]["parameters"] == {"q": ["café"]}
    assert result.decoded["http"]["form"]["charset"] == "utf-8"


def test_raw_form_bytes_are_used_instead_of_replacement_body_text():
    event = make_http_event(body=b"q=\xff", content_type=b"application/x-www-form-urlencoded")
    assert "�" in event.application.fields["body"]
    result = decode_event(event, DecoderConfig(invalid_bytes_policy="strict"))
    assert result.decode_status == "error"
    assert result.decoded["http"]["form"]["parameters"] is None
    assert result.errors[0].code == "invalid_character_sequence"


@pytest.mark.parametrize("content_type", [b"text/plain", b"application/json"])
def test_non_form_content_type_does_not_trigger_form_decoding(content_type):
    event = make_http_event(body=b"q=a+b", content_type=content_type)
    assert decode_event(event).decoded["http"]["form"] is None


@pytest.mark.parametrize("raw, code", [(None, "missing_raw_form_body"), ("!", "invalid_form_base64")])
def test_bad_form_base64_produces_reason_and_next_event_continues(raw, code):
    event = make_http_event(body=b"q=value", content_type=b"application/x-www-form-urlencoded")
    event.application.fields["body_base64"] = raw
    results = [decode_event(item) for item in (event, make_http_event(b"/next"))]
    assert results[0].decode_status == "error"
    assert results[0].errors[0].code == code
    assert results[0].reason
    assert results[1].decode_status == "ok"


def test_http_form_body_limit_is_reported_even_when_uri_is_valid():
    event = make_http_event(body=b"q=long-value", content_type=b"application/x-www-form-urlencoded")
    result = decode_event(event, DecoderConfig(max_input_bytes=4))
    assert result.decoded["http"]["uri"]["status"] == "ok"
    assert result.decoded["http"]["form"]["status"] == "skipped"
    assert result.decode_status == "partial"
    assert result.reason


def test_incomplete_http_message_is_not_reported_as_complete_decode():
    event = make_http_event(
        body=b"q=short", content_type=b"application/x-www-form-urlencoded", content_length=20
    )
    result = decode_event(event)
    assert result.decode_status == "partial"
    assert any(error.code == "incomplete_http_message" for error in result.errors)
    assert result.packet.parse_status == "partial"


def test_malformed_http_fields_and_headers_do_not_raise():
    event = PacketEvent(1, "2026-10-09T00:00:00Z", CaptureSource("pcap", "bad.pcap"), 0)
    event.application = ApplicationInfo("HTTP", "request", [])
    assert decode_event(event).decode_status == "error"
    event.application.fields = {"target": "/", "headers": []}
    assert decode_event(event).decode_status == "error"
