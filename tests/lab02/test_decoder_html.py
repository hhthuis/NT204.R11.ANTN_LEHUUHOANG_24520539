import base64
import json

import pytest

from ids.config import DecoderConfig
from ids.decoders.decoder import decode_event
from ids.decoders.html import decode_html
from ids.models import ApplicationInfo, CaptureSource, PacketEvent
from tests.lab02.test_decoder_http import make_http_event


@pytest.mark.parametrize("raw, expected", [
    (b"&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", '<script>alert("x")</script>'),
    (b"&amp; &quot; &apos; &#39;", '& " \' \''),
    (b"&#60;script&#62;", "<script>"),
    (b"&#x3c;script&#X3E;", "<script>"),
    (b"&nbsp;&copy;", "\u00a0©"),
    (b"&amp;lt;script&amp;gt;", "&lt;script&gt;"),
    (b"&#38;lt;", "&lt;"),
    (b"&unknown; & &#xZZ;", "&unknown; & &#xZZ;"),
    (b"&lt test", "< test"),
    (b"%3C+a+b", "%3C+a+b"),
    ("Việt Nam &lt;3".encode(), "Việt Nam <3"),
    (b"", ""),
])
def test_html5_entities_decode_once(raw, expected):
    result = decode_html(raw)
    assert result.text == expected
    assert result.status == "ok"
    assert result.errors == []


@pytest.mark.parametrize("raw", [
    b"&#0;", b"&#xD800;", b"&#55296;", b"&#1114112;", b"&#x110000;",
    b"&#" + b"9" * 5000 + b";",
])
def test_invalid_numeric_scalars_are_safe_and_reported(raw):
    result = decode_html(raw)
    assert result.text == "�"
    assert result.status == "partial"
    assert [error.code for error in result.errors] == ["invalid_html_entity"]


def test_many_leading_zeros_do_not_exceed_python_integer_conversion_limit():
    assert decode_html(b"&#" + b"0" * 5000 + b"65;").text == "A"
    result = decode_html(b"&#0;&#xD800;&#x110000;")
    assert result.text == "���"
    assert len(result.errors) == 1


@pytest.mark.parametrize("policy, status, text", [
    ("replace", "partial", "�<b>"), ("strict", "error", None),
])
def test_invalid_bytes_use_configured_policy(policy, status, text):
    result = decode_html(b"\xff&lt;b&gt;", DecoderConfig(invalid_bytes_policy=policy))
    assert result.status == status
    assert result.text == text
    assert result.errors[0].code == "invalid_character_sequence"
    assert decode_html(b"&lt;next&gt;").text == "<next>"


@pytest.mark.parametrize("raw", [None, "&lt;b&gt;", 123])
def test_html_input_requires_raw_bytes(raw):
    result = decode_html(raw)
    assert result.status == "error"
    assert result.errors[0].code == "invalid_text_input"


def test_ascii_and_charset_aliases_and_unsupported_charsets():
    assert decode_html(b"&copy;", charset="US-ASCII").text == "©"
    assert decode_html(b"&lt;", charset="UTF8").charset == "utf-8"
    result = decode_html(b"&lt;", charset="latin-1")
    assert result.status == "error"
    assert result.errors[0].code == "unsupported_charset"


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_html_limits_input_before_unescape(policy, status, monkeypatch):
    def unexpected_call(*args):
        raise AssertionError("Unescape should not run on oversized input")
    monkeypatch.setattr("ids.decoders.html.unescape", unexpected_call)
    result = decode_html(b"&lt;", DecoderConfig(max_input_bytes=3, limit_policy=policy))
    assert result.status == status
    assert result.text is None
    assert result.errors[0].code == "input_limit_exceeded"


def test_output_limit_applies_after_entities_contract_and_counts_utf8_bytes():
    assert decode_html(b"&lt;", DecoderConfig(max_output_bytes=1)).text == "<"
    assert decode_html(b"&copy;", DecoderConfig(max_output_bytes=2)).text == "©"
    assert decode_html(b"&#x1F600;", DecoderConfig(max_output_bytes=4)).text == "😀"


@pytest.mark.parametrize("policy, status", [("skip", "skipped"), ("error", "error")])
def test_output_limit_discards_entire_text_retaining_errors(policy, status):
    result = decode_html(
        b"\xff&#0;", DecoderConfig(max_output_bytes=5, limit_policy=policy)
    )
    assert result.text is None
    assert result.status == status
    assert [error.code for error in result.errors] == [
        "invalid_character_sequence", "invalid_html_entity", "output_limit_exceeded",
    ]


@pytest.mark.parametrize("content_type", [b"text/html", b'TeXt/PlAiN; charset="UTF8"'])
def test_event_body_uses_original_base64_and_preserves_raw_snapshot(content_type):
    body = b"&lt;script&gt;&amp;lt; a+b"
    event = make_http_event(target=b"/a+b?q=&lt;x&gt;", body=body, content_type=content_type)
    original = event.to_dict()
    result = decode_event(event)
    saved = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))
    assert saved["decoded"]["http"]["html"]["text"] == "<script>&lt; a+b"
    assert saved["decoded"]["http"]["uri"]["text"] == "/a+b?q=&lt;x&gt;"
    assert saved["packet"] == original == event.to_dict()
    assert base64.b64decode(saved["packet"]["application"]["fields"]["body_base64"]) == body
    assert result.decode_status == "ok"


def response_event(body, content_type="text/html; charset=utf-8"):
    return PacketEvent(
        packet_id=1, timestamp="2026-10-09T00:00:00.000000Z",
        source=CaptureSource("pcap", "html.pcap"), captured_length=len(body),
        application=ApplicationInfo("HTTP", "response", {
        "headers": {"Content-Type": content_type}, "body_length": len(body),
        "body_base64": base64.b64encode(body).decode() if body else None,
        "body": "Do not decode this lossy preview", "message_complete": True,
        }),
    )


def test_response_and_empty_body_have_html_results_without_uri():
    result = decode_event(response_event(b"&lt;b&gt;"))
    assert result.decoded["http"]["html"]["text"] == "<b>"
    assert result.decoded["http"]["uri"] is None
    assert result.decode_status == "ok"
    empty = decode_event(response_event(b""))
    assert empty.decoded["http"]["html"]["text"] == ""
    assert empty.decode_status == "ok"


def test_character_header_override_and_invalid_bytes_not_hidden_by_parser_body():
    result = decode_event(response_event("café &lt;".encode()), DecoderConfig(default_charset="ascii"))
    assert result.decoded["http"]["html"]["text"] == "café <"
    result = decode_event(response_event(b"\xff&lt;"), DecoderConfig(invalid_bytes_policy="strict"))
    assert result.decode_status == "error"
    assert result.decoded["http"]["html"]["text"] is None
    assert result.reason and result.errors[0].code == "invalid_character_sequence"


@pytest.mark.parametrize("content_type", [
    None, b"application/json", b"application/octet-stream", b"text/css", b"application/xml",
])
def test_other_body_types_are_not_unescaped(content_type):
    event = make_http_event(body=b"&lt;b&gt;", content_type=content_type)
    assert decode_event(event).decoded["http"]["html"] is None


def test_form_values_do_not_receive_html_unescape():
    event = make_http_event(body=b"q=%26lt%3B", content_type=b"application/x-www-form-urlencoded")
    result = decode_event(event)
    assert result.decoded["http"]["form"]["parameters"] == {"q": ["&lt;"]}
    assert result.decoded["http"]["html"] is None


@pytest.mark.parametrize("raw, code", [
    (None, "missing_raw_html_body"), ("!", "invalid_html_base64"),
    (123, "invalid_html_base64"),
])
def test_missing_or_invalid_base64_is_reported_and_next_event_continues(raw, code):
    event = response_event(b"&lt;")
    event.application.fields["body_base64"] = raw
    result = decode_event(event)
    assert result.decode_status == "error"
    assert result.reason and result.errors[0].code == code
    assert decode_event(response_event(b"&lt;next&gt;")).decode_status == "ok"


def test_base64_allocation_is_bounded_before_decode(monkeypatch):
    event = response_event(b"&lt;")
    def unexpected_call(*args, **kwargs):
        raise AssertionError("Base64 should not allocate oversized body")
    monkeypatch.setattr("ids.decoders.http.base64.b64decode", unexpected_call)
    result = decode_event(event, DecoderConfig(max_input_bytes=1))
    assert result.decode_status == "skipped"
    assert result.reason and result.errors[0].code == "input_limit_exceeded"


def test_request_with_skipped_body_keeps_successful_uri_and_marks_partial():
    event = make_http_event(body=b"&copy;", content_type=b"text/html")
    result = decode_event(event, DecoderConfig(max_output_bytes=1))
    assert result.decode_status == "partial"
    assert result.decoded["http"]["uri"]["text"] == "/"
    assert result.decoded["http"]["html"]["text"] is None
    assert result.reason and result.errors[0].code == "output_limit_exceeded"


@pytest.mark.parametrize("header, value, status, code", [
    ("Content-Encoding", "gzip", "skipped", "unsupported_http_body_encoding"),
    ("Transfer-Encoding", "chunked", "skipped", "unsupported_http_body_encoding"),
    ("Content-Encoding", 123, "error", "invalid_http_body_encoding"),
])
def test_encoded_body_is_not_misinterpreted_as_plain_html(header, value, status, code):
    event = response_event(b"&lt;")
    event.application.fields["headers"][header] = value
    result = decode_event(event)
    assert result.decode_status == status
    assert result.decoded["http"]["html"]["text"] is None
    assert result.reason and result.errors[0].code == code


def test_incomplete_body_is_partial_and_keeps_available_decoded_text():
    event = make_http_event(body=b"&lt;b&gt;", content_type=b"text/html", content_length=100)
    result = decode_event(event)
    assert result.decode_status == "partial"
    assert result.decoded["http"]["html"]["text"] == "<b>"
    assert result.reason and result.errors[0].code == "incomplete_http_message"
