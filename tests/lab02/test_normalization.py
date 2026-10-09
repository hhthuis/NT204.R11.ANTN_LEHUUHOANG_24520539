import json
from copy import deepcopy

import pytest

from ids.config import ConfigError, PreprocessorConfig, load_config
from ids.decoders.decoder import decode_event
from ids.models import ApplicationInfo
from ids.preprocessors.normalization import (
    normalize_domain, normalize_flags, normalize_headers, normalize_ip,
    normalize_packet, normalize_protocol, normalize_timestamp, normalize_uri,
)
from ids.preprocessors.preprocessor import preprocess_event
from ids.processing_models import ProcessedEvent
from tests.lab02.test_decoder_http import make_http_event
from tests.lab02.test_validation import make_packet


@pytest.mark.parametrize("raw, expected", [(" tcp ", "TCP"), ("HtTp", "HTTP"), (" IPV4 ", "IPv4"), ("ipv6", "IPv6")])
def test_protocol_names_have_a_canonical_spelling(raw, expected):
    assert normalize_protocol(raw).value == expected


@pytest.mark.parametrize("raw, expected", [
    (" 10.0.0.1 ", "10.0.0.1"), ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
])
def test_ip_representation_is_canonical_without_guessed_addresses(raw, expected):
    assert normalize_ip(raw).value == expected


@pytest.mark.parametrize("raw", ["2026-10-09T00:00:00Z", "2026-10-09T07:00:00+07:00", "2026-10-08T20:00:00-04:00"])
def test_same_instant_has_one_utc_microsecond_representation(raw):
    assert normalize_timestamp(raw).value == "2026-10-09T00:00:00.000000Z"


@pytest.mark.parametrize("raw, expected", [
    (" Example.COM. ", "example.com"), ("_SIP._TCP.Example.COM", "_sip._tcp.example.com"),
    ("bücher.Example", "bücher.example"), ("BÜCHER.example", "bÜcher.example"),
])
def test_domain_ascii_case_is_normalized_without_another_unicode_mapping(raw, expected):
    assert normalize_domain(raw).value == expected


def test_dns_root_is_normalized_only_in_dns_context():
    assert normalize_domain("", dns_root=True).value == "."
    assert normalize_domain(".", dns_root=True).value == "."
    assert normalize_domain("").errors


@pytest.mark.parametrize("function, raw", [
    (normalize_protocol, 6), (normalize_protocol, ""), (normalize_protocol, "TCP UDP"),
    (normalize_ip, 167772161), (normalize_ip, "999.0.0.1"),
    (normalize_timestamp, "2026-10-09"), (normalize_timestamp, "0001-01-01T00:00:00+14:00"),
    (normalize_domain, "example..com"), (normalize_domain, "bad/name"),
    (normalize_domain, "example.com.."), (normalize_domain, "bad\x00name"),
])
def test_bad_text_fields_return_none_and_preprocess_error(function, raw):
    result = function(raw)
    assert result.value is None and result.errors
    assert all(error.stage == "preprocess" and error.code.startswith("normalization_") for error in result.errors)


@pytest.mark.parametrize("function", [normalize_protocol, normalize_ip, normalize_timestamp, normalize_domain, normalize_headers, normalize_flags])
def test_missing_optional_value_is_not_invented(function):
    result = function(None)
    assert result.value is None and result.errors == []


def test_headers_preserve_values_and_case_collisions_as_ordered_lists():
    raw = {"X-Token": "AbC", "x-token": ["DeF", ""], " Content-Type ": "Text/Plain; charset=UTF8"}
    original = deepcopy(raw)
    result = normalize_headers(raw)
    assert result.value == {"x-token": ["AbC", "DeF", ""], "content-type": ["Text/Plain; charset=UTF8"]}
    assert raw == original
    assert normalize_headers({"x-token": ["a", "b"]}).value == {"x-token": ["a", "b"]}


@pytest.mark.parametrize("raw", [[], {"bad\r\nname": "value"}, {"Name": 123}, {"Name": ["value", None]}, {123: "value"}])
def test_invalid_headers_do_not_create_a_partial_silent_dictionary(raw):
    result = normalize_headers(raw)
    assert result.value is None and result.errors


def test_flags_are_deduplicated_and_sorted_in_bit_order():
    assert normalize_flags(["ack", " SYN ", "syn", "fin"]).value == ["FIN", "SYN", "ACK"]
    assert normalize_flags([]).value == []
    assert normalize_flags(["SYN", "BOGUS"]).value is None
    assert normalize_flags("SYN").errors


@pytest.mark.parametrize("raw, target, path, query, form", [
    ("/Admin%2fA?q=x+y&tag=a&tag=b&x=%26", "/Admin%2FA?q=x+y&tag=a&tag=b&x=%26", "/Admin%2FA", "q=x+y&tag=a&tag=b&x=%26", "origin"),
    ("/%252f", "/%252f", "/%252f", None, "origin"),
    ("/a//b/../c?", "/a//b/../c?", "/a//b/../c", "", "origin"),
    ("//path/a", "//path/a", "//path/a", None, "origin"),
    ("/café", "/caf%C3%A9", "/caf%C3%A9", None, "origin"),
    (b"/x\xff", "/x%FF", "/x%FF", None, "origin"),
    ("*", "*", "*", None, "asterisk"),
    ("HTTP://Example.COM/Admin%2fA?q=x+y", "HTTP://Example.COM/Admin%2FA?q=x+y", "/Admin%2FA", "q=x+y", "absolute"),
    ("Example.COM:000080", "Example.COM:000080", None, None, "authority"),
    ("[2001:db8::1]:443", "[2001:db8::1]:443", None, None, "authority"),
])
def test_uri_is_normalized_from_raw_without_decoding_or_changing_delimiters(raw, target, path, query, form):
    result = normalize_uri(raw)
    assert result.errors == []
    assert result.value == {"target": target, "path": path, "query": query, "target_form": form}


@pytest.mark.parametrize("raw", [
    None, "", "/%ZZ", "/bad path", "/tab\tx", "/a#fragment", "/\ud800",
    "http://[bad]/x", "http://host:70000/x", "host:70000", "relative/path",
])
def test_malformed_or_unsupported_uri_has_reason_instead_of_silent_repair(raw):
    result = normalize_uri(raw)
    assert result.value is None and result.errors


def test_text_limits_count_utf8_bytes_and_post_normalization_expansion():
    assert normalize_domain("é", PreprocessorConfig(max_input_bytes=1)).value is None
    assert normalize_timestamp("2026-10-09T00:00:00Z", PreprocessorConfig(max_output_bytes=20)).value is None
    assert normalize_uri(b"/\xff", PreprocessorConfig(max_output_bytes=3)).value is None
    assert normalize_uri(b"/\xff", PreprocessorConfig(max_output_bytes=4)).value["target"] == "/%FF"
    assert normalize_domain("\ud800").errors[0].code == "normalization_invalid_unicode"


def test_collection_limits_include_json_structure_and_discard_the_whole_field():
    raw = {"X": "a"}
    assert normalize_headers(raw, PreprocessorConfig(max_input_bytes=8)).value is None
    assert normalize_headers(raw, PreprocessorConfig(max_input_bytes=9, max_output_bytes=11)).value == {"x": ["a"]}
    assert normalize_headers(raw, PreprocessorConfig(max_output_bytes=10)).value is None
    assert normalize_flags(["SYN"], PreprocessorConfig(max_output_bytes=6)).value is None


def test_preprocessor_preserves_raw_and_decoded_uri_views_without_double_decoding():
    packet = make_http_event(target=b"/Admin%2fA?q=x+y&x=%252f", body=b"&lt;", content_type=b"text/plain")
    decoded = decode_event(packet)
    original = deepcopy(decoded.to_dict())
    processed = preprocess_event(decoded)
    saved = json.loads(json.dumps(processed.to_dict(), ensure_ascii=False))
    assert saved["packet"] == original["packet"] and saved["decoded"] == original["decoded"]
    assert decoded.to_dict() == original
    assert processed.decoded["http"]["uri"]["text"] == "/Admin/A?q=x+y&x=%2f"
    assert processed.normalized["application"]["fields"]["uri"]["target"] == "/Admin%2FA?q=x+y&x=%252f"
    assert processed.normalized["application"]["fields"]["headers"]["content-type"] == ["text/plain"]
    assert processed.preprocess_status == "valid" and processed.processing_action == "skip_tracking" and processed.flow is None
    processed.normalized["application"]["fields"]["headers"]["content-type"].append("changed")
    assert decoded.packet.application.fields["headers"]["content-type"] == "text/plain"


def test_http_parser_latin1_target_recovers_literal_utf8_bytes_once():
    packet = make_http_event(target=b"/caf\xc3\xa9")
    processed = preprocess_event(decode_event(packet))
    assert processed.normalized["application"]["fields"]["uri"]["target"] == "/caf%C3%A9"
    assert processed.decoded["http"]["uri"]["text"] == "/café"


def test_dns_question_record_names_and_domain_rdata_are_normalized_but_txt_is_preserved():
    packet = make_packet()
    packet.application = ApplicationInfo("dns", "response", {
        "questions": [{"name": "Example.COM.", "type": "a", "class": "in"}],
        "answers": [
            {"name": "WWW.Example.COM", "type": "cname", "data": "Target.Example.COM."},
            {"name": "Example.COM", "type": "AAAA", "data": "2001:0DB8::1"},
            {"name": "Example.COM", "type": "TXT", "data": ["KeepCASE", "a+b"]},
        ],
    })
    original = packet.to_dict()
    normalized = preprocess_event(ProcessedEvent(packet=packet)).normalized["application"]["fields"]
    assert normalized["questions"][0] == {"name": "example.com", "type": "A", "class": "IN"}
    assert normalized["answers"][0]["data"] == "target.example.com"
    assert normalized["answers"][1]["data"] == "2001:db8::1"
    assert normalized["answers"][2]["data"] == ["KeepCASE", "a+b"]
    assert packet.to_dict() == original


@pytest.mark.parametrize("name, mailbox, expected", [
    ("MAIL FROM", "Alice@Example.COM.", "Alice@example.com"),
    ("RCPT TO", '"A@B"@Example.COM', '"A@B"@example.com'),
    ("MAIL FROM", "", ""),
    ("RCPT TO", "Bob@[192.0.2.1]", "Bob@[192.0.2.1]"),
    ("RCPT TO", "Bob@[ipv6:2001:0DB8::1]", "Bob@[IPv6:2001:db8::1]"),
])
def test_smtp_mailbox_local_part_is_preserved(name, mailbox, expected):
    packet = make_packet()
    packet.application = ApplicationInfo("smtp", "command", {"commands": [{"command": name.lower(), "mailbox": mailbox}]})
    processed = preprocess_event(ProcessedEvent(packet=packet))
    assert processed.normalized["application"]["fields"]["commands"][0]["mailbox"] == expected
    assert processed.preprocess_status == "valid"


def test_smtp_helo_domain_and_mime_header_names_are_normalized():
    packet = make_packet()
    packet.application = ApplicationInfo("smtp", "command", {"command": "ehlo", "domain": "Client.Example.COM."})
    assert preprocess_event(ProcessedEvent(packet=packet)).normalized["application"]["fields"]["commands"] == [{"command": "EHLO", "domain": "client.example.com"}]
    packet.application = ApplicationInfo("MIME", "message", {"headers": {"Content-Type": ["Text/Plain"], "X-Tag": ["AbC", "DeF"]}})
    assert preprocess_event(ProcessedEvent(packet=packet)).normalized["application"]["fields"]["headers"]["x-tag"] == ["AbC", "DeF"]


def test_invalid_required_fields_remain_invalid_and_never_get_default_endpoint_or_time():
    packet = make_packet()
    packet.network.src_ip = "bad"
    packet.transport.dst_port = -1
    packet.timestamp = "bad"
    processed = preprocess_event(ProcessedEvent(packet=packet))
    assert processed.preprocess_status == "invalid"
    assert processed.normalized["network"]["src_ip"] is None
    assert processed.normalized["transport"]["dst_port"] is None
    assert processed.normalized["timestamp"] is None
    assert processed.reason and processed.processing_action == "skip_tracking"
    assert preprocess_event(ProcessedEvent(packet=make_packet())).preprocess_status == "valid"


def test_normalization_errors_are_partial_and_preserve_successful_fields():
    packet = make_http_event(target=b"/%ZZ")
    processed = preprocess_event(decode_event(packet))
    assert processed.preprocess_status == "partial"
    assert processed.decode_status == "partial"
    assert processed.normalized["application"]["fields"]["uri"] is None
    assert processed.normalized["network"]["src_ip"] == "10.0.0.1"
    assert {error.stage for error in processed.errors} == {"decode", "preprocess"}


def test_repeated_preprocessing_is_idempotent_and_resolved_errors_do_not_linger():
    packet = make_http_event(target=b"/%ZZ")
    event = ProcessedEvent(packet=packet, reason="operator note")
    first = preprocess_event(event)
    assert preprocess_event(first).to_dict() == first.to_dict()
    first.packet.application.fields["target"] = "/OK"
    fixed = preprocess_event(first)
    assert fixed.errors == [] and fixed.reason == "operator note" and fixed.preprocess_status == "valid"


def test_bad_application_collections_return_safe_fields_without_crashing():
    packet = make_packet()
    packet.application = ApplicationInfo("DNS", "response", {"questions": "bad", "answers": [123, {"name": "bad/name", "type": "A", "data": "999.0.0.1"}]})
    processed = preprocess_event(ProcessedEvent(packet=packet))
    assert processed.preprocess_status == "partial"
    fields = processed.normalized["application"]["fields"]
    assert fields["questions"] is None and fields["answers"][0] is None
    packet.application = ApplicationInfo("SMTP", "command", {"commands": [123, {"command": "MAIL FROM", "mailbox": "bad"}]})
    assert preprocess_event(ProcessedEvent(packet=packet)).preprocess_status == "partial"


def test_collection_limits_do_not_return_truncated_dns_records():
    packet = make_packet()
    packet.application = ApplicationInfo("DNS", "query", {"questions": [{"name": "example.com", "type": "A"}]})
    config = PreprocessorConfig(max_input_bytes=30)
    processed = preprocess_event(ProcessedEvent(packet=packet), config)
    assert processed.normalized["application"]["fields"]["questions"] is None
    assert processed.preprocess_status == "partial"


def test_missing_models_are_not_fabricated_and_wrong_packet_model_is_safe():
    packet = make_packet()
    packet.network = packet.transport = packet.application = None
    processed = preprocess_event(ProcessedEvent(packet=packet))
    assert processed.normalized["network"] is None and processed.normalized["transport"] is None
    assert processed.normalized["application"] is None and processed.preprocess_status == "invalid"
    assert normalize_packet({}).value is None


@pytest.mark.parametrize("field, value", [("max_input_bytes", 0), ("max_input_bytes", True), ("max_output_bytes", -1), ("max_output_bytes", 1.5)])
def test_preprocessor_limits_are_validated(field, value):
    with pytest.raises(ConfigError, match="preprocessor." + field):
        PreprocessorConfig(**{field: value})


def test_preprocessor_limits_can_be_loaded_from_toml(tmp_path):
    path = tmp_path / "processing.toml"
    path.write_text("[preprocessor]\nmax_input_bytes=256\nmax_output_bytes=128\n")
    config = load_config(path).preprocessor
    assert config.max_input_bytes == 256 and config.max_output_bytes == 128
