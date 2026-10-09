import json
from copy import deepcopy

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP

from ids.decoders.decoder import decode_event
from ids.flows.models import FlowAssociation, FlowDirection, TcpState
from ids.models import ApplicationInfo, CaptureSource, NetworkInfo, PacketEvent, ParseError, TransportInfo
from ids.pipeline import parse_packet
from ids.preprocessors.validation import validate_event, validate_packet
from ids.processing_models import DecodeStatus, ProcessedEvent, ProcessingAction, ProcessingError, ProcessingStage


def make_packet():
    return PacketEvent(
        packet_id=1, timestamp="2026-10-09T00:00:00Z", captured_length=54,
        source=CaptureSource("pcap", "validation.pcap"),
        network=NetworkInfo("IPv4", "10.0.0.1", "10.0.0.2"),
        transport=TransportInfo("TCP", 51000, 8080, {"flags": ["SYN"]}),
    )


def change_field(packet, path, value):
    parts = path.split(".")
    parent = packet
    for part in parts[:-1]:
        parent = getattr(parent, part)
    setattr(parent, parts[-1], value)


@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
def test_valid_metadata_with_empty_payload_and_unknown_application(protocol):
    packet = make_packet()
    packet.transport.protocol = protocol
    original = packet.to_dict()
    result = validate_packet(packet)
    assert result.status == "valid" and result.tracking_eligible
    assert result.errors == [] and result.reason is None
    assert packet.to_dict() == original


@pytest.mark.parametrize("timestamp", [
    "2026-10-09T00:00:00Z", "2026-10-09T07:00:00+07:00",
    "2026-10-09T00:00:00.123456-04:00", " 2026-10-09T00:00:00+00:00 ",
])
def test_timezone_aware_timestamp_is_accepted_without_normalizing_raw(timestamp):
    packet = make_packet()
    packet.timestamp = timestamp
    assert validate_packet(packet).status == "valid"
    assert packet.timestamp == timestamp


@pytest.mark.parametrize("timestamp", [
    None, 123, "", "not a date", "2026-02-30T00:00:00Z", "2026-10-09",
    "2026-10-09T00:00:00", "0001-01-01T00:00:00+14:00",
    "9999-12-31T23:59:59-14:00",
])
def test_invalid_or_timezone_naive_timestamp_blocks_tracking(timestamp):
    packet = make_packet()
    packet.timestamp = timestamp
    result = validate_packet(packet)
    assert result.status == "invalid" and not result.tracking_eligible
    assert result.errors[0].code == "validation_invalid_timestamp"


@pytest.mark.parametrize("path, value, code", [
    ("packet_id", 0, "invalid_packet_id"), ("packet_id", True, "invalid_packet_id"),
    ("packet_id", "1", "invalid_packet_id"),
    ("captured_length", -1, "invalid_captured_length"),
    ("captured_length", True, "invalid_captured_length"),
    ("captured_length", 54.0, "invalid_captured_length"),
    ("network", None, "missing_network"), ("network", {}, "missing_network"),
    ("transport", None, "missing_transport"), ("transport", {}, "missing_transport"),
    ("network.protocol", None, "invalid_network_protocol"),
    ("network.protocol", " ", "invalid_network_protocol"),
    ("transport.protocol", 6, "invalid_transport_protocol"),
    ("network.src_ip", None, "invalid_ip_address"),
    ("network.dst_ip", "999.1.1.1", "invalid_ip_address"),
    ("network.src_ip", 167772161, "invalid_ip_address"),
    ("network.dst_ip", "2001:db8::1", "ip_protocol_mismatch"),
    ("transport.src_port", -1, "invalid_port"),
    ("transport.dst_port", 65536, "invalid_port"),
    ("transport.src_port", True, "invalid_port"),
    ("transport.dst_port", "80", "invalid_port"),
    ("transport.dst_port", 80.0, "invalid_port"),
    ("parse_status", "malformed", "malformed_packet"),
    ("parse_status", None, "invalid_parse_status"),
])
def test_missing_or_invalid_required_fields_have_structured_errors(path, value, code):
    packet = make_packet()
    change_field(packet, path, value)
    result = validate_packet(packet)
    assert result.status == "invalid" and not result.tracking_eligible
    assert "validation_" + code in [error.code for error in result.errors]
    assert result.reason and all(error.stage == "preprocess" for error in result.errors)


@pytest.mark.parametrize("port", [0, 65535])
def test_port_range_boundaries(port):
    packet = make_packet()
    packet.transport.src_port = packet.transport.dst_port = port
    assert validate_packet(packet).status == "valid"


def test_mixed_case_protocol_and_whitespace_are_checked_without_rewriting_raw():
    packet = make_packet()
    packet.network.protocol = " ipv4 "
    packet.network.src_ip = " 10.0.0.1 "
    packet.transport.protocol = " tcp "
    packet.transport.fields["flags"] = [" syn "]
    packet.application.protocol = " unknown "
    packet.parse_status = " OK "
    original = packet.to_dict()
    assert validate_packet(packet).status == "valid"
    assert packet.to_dict() == original


@pytest.mark.parametrize("path, value, code", [
    ("transport.protocol", "SCTP", "unsupported_transport_protocol"),
    ("parse_status", "unsupported", "unsupported_packet"),
    ("network.fragment_offset", 1, "noninitial_fragment"),
    ("network.fragment_offset", -1, "invalid_fragment_offset"),
    ("transport.fields", [], "invalid_transport_fields"),
])
def test_partial_metadata_that_is_unsafe_for_tracking(path, value, code):
    packet = make_packet()
    change_field(packet, path, value)
    result = validate_packet(packet)
    assert result.status == "partial" and not result.tracking_eligible
    assert "validation_" + code in [error.code for error in result.errors]


def test_ipv6_is_recognized_as_unsupported_instead_of_invalid_address():
    packet = make_packet()
    packet.network.protocol = "IPv6"
    packet.network.src_ip, packet.network.dst_ip = "2001:db8::1", "2001:db8::2"
    result = validate_packet(packet)
    assert result.status == "partial" and not result.tracking_eligible
    assert [error.code for error in result.errors] == ["validation_unsupported_network_protocol"]


@pytest.mark.parametrize("path, value, code", [
    ("wire_length", -1, "invalid_wire_length"),
    ("wire_length", 53, "invalid_wire_length"),
    ("wire_length", True, "invalid_wire_length"),
    ("source", None, "invalid_capture_source"),
    ("source.name", "", "invalid_capture_source"),
    ("source.type", "synthetic", "unsupported_capture_source"),
    ("network.ttl", 256, "invalid_ttl"),
    ("payload", None, "missing_payload_info"),
    ("payload.length", -1, "invalid_payload_length"),
    ("payload.length", 55, "invalid_payload_length"),
    ("payload.base64", 123, "invalid_payload_representation"),
    ("application", None, "missing_application_info"),
    ("application.protocol", None, "invalid_application_protocol"),
    ("application.protocol", "FTP", "unsupported_application_protocol"),
    ("application.fields", [], "invalid_application_fields"),
    ("parse_status", "partial", "partial_packet"),
])
def test_optional_data_issues_are_partial_but_keep_valid_flow_endpoints(path, value, code):
    packet = make_packet()
    change_field(packet, path, value)
    result = validate_packet(packet)
    assert result.status == "partial" and result.tracking_eligible
    assert "validation_" + code in [error.code for error in result.errors]


@pytest.mark.parametrize("flags", ["SYN", [1], ["BOGUS"], {}])
def test_invalid_tcp_flags_block_state_tracking(flags):
    packet = make_packet()
    packet.transport.fields["flags"] = flags
    result = validate_packet(packet)
    assert result.status == "partial" and not result.tracking_eligible
    assert result.errors[0].code == "validation_invalid_tcp_flags"


def test_missing_and_duplicate_flags_are_partial_and_do_not_invent_state():
    packet = make_packet()
    packet.transport.fields = {}
    result = validate_packet(packet)
    assert result.status == "partial" and result.tracking_eligible
    assert result.errors[0].code == "validation_missing_tcp_flags"
    packet.transport.fields["flags"] = ["SYN", "syn"]
    assert validate_packet(packet).errors[0].code == "validation_duplicate_tcp_flags"
    packet.transport.fields["flags"] = []
    assert validate_packet(packet).status == "valid"


def test_parser_lower_layer_errors_block_tracking_but_application_errors_do_not():
    packet = make_packet()
    packet.parse_status = "partial"
    packet.errors = [ParseError("http", "incomplete message")]
    assert validate_packet(packet).tracking_eligible
    packet.errors.append(ParseError("transport", "untrusted header"))
    result = validate_packet(packet)
    assert result.status == "partial" and not result.tracking_eligible
    assert result.errors[-1].code == "validation_unsafe_lower_layer_parse"


def test_multiple_issues_are_reported_and_invalid_takes_precedence():
    packet = make_packet()
    packet.transport.src_port = -1
    packet.network.dst_ip = "bad"
    packet.application.protocol = "FTP"
    result = validate_packet(packet)
    assert result.status == "invalid" and not result.tracking_eligible
    assert len(result.errors) == 3


def test_wrong_event_type_returns_invalid_without_exception():
    assert validate_packet({}).status == "invalid"
    assert not validate_packet(None).tracking_eligible


def test_nonempty_payload_missing_raw_is_partial_without_requiring_application_decode():
    packet = make_packet()
    packet.payload.length = 4
    result = validate_packet(packet)
    assert result.status == "partial" and result.tracking_eligible
    assert result.errors[0].code == "validation_missing_raw_payload"


def test_validation_preserves_decode_errors_and_raw_without_authorizing_tracking():
    packet = make_packet()
    packet.transport.dst_port = -1
    decoded = ProcessedEvent(
        packet=packet, decoded={"payload": {"text": "�"}}, decode_status=DecodeStatus.PARTIAL,
        errors=[ProcessingError(ProcessingStage.DECODE, "invalid_character_sequence", "bad UTF-8")],
        reason="bad UTF-8", flow=FlowAssociation("old", FlowDirection.FORWARD, TcpState.NEW),
        processing_action=ProcessingAction.TRACK,
    )
    original = deepcopy(decoded.to_dict())
    result = validate_event(decoded)
    saved = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))
    assert decoded.to_dict() == original
    assert saved["packet"] == original["packet"] and saved["decoded"] == original["decoded"]
    assert saved["decode_status"] == "partial" and saved["preprocess_status"] == "invalid"
    assert result.processing_action == "skip_tracking" and result.flow is None
    assert result.errors[0].stage == "decode" and "bad UTF-8" in result.reason
    assert saved["normalized"] == {}
    result.packet.network.src_ip = "changed"
    assert decoded.packet.network.src_ip == "10.0.0.1"


def test_repeat_validation_replaces_old_validation_errors_and_preserves_other_reasons():
    event = ProcessedEvent(packet=make_packet(), reason="operator note")
    event.packet.timestamp = "bad"
    first = validate_event(event)
    assert validate_event(first).to_dict() == first.to_dict()
    first.packet.timestamp = "2026-10-09T00:00:00Z"
    first.errors.append(ProcessingError(ProcessingStage.PREPROCESS, "normalization_warning", "other stage"))
    fixed = validate_event(first)
    assert fixed.preprocess_status == "valid"
    assert [error.code for error in fixed.errors] == ["normalization_warning"]
    assert "operator note" in fixed.reason
    assert "valid ISO datetime" not in fixed.reason


@pytest.mark.parametrize("layer", [TCP(flags="S"), TCP(flags="SA"), TCP(flags="A"), UDP()])
def test_real_parser_decoder_validation_accepts_empty_transport_packets(layer):
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / layer
    parsed = parse_packet(packet, 1, CaptureSource("pcap", "empty.pcap"))
    processed = validate_event(decode_event(parsed))
    assert processed.preprocess_status == "valid"
    assert processed.decode_status == "skipped"
    assert processed.errors == []


def test_decoder_failure_does_not_make_good_transport_metadata_invalid_and_next_event_continues():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=9999, flags="PA") / Raw(b"\xff")
    parsed = parse_packet(packet, 1, CaptureSource("pcap", "invalid-bytes.pcap"))
    event = validate_event(decode_event(parsed))
    assert event.preprocess_status == "valid" and event.decode_status == "partial"
    assert event.errors[0].stage == "decode" and event.reason
    assert validate_event(ProcessedEvent(packet=make_packet())).preprocess_status == "valid"
