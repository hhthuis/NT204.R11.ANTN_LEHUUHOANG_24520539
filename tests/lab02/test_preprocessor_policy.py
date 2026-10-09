"""Policy tests use decisions, preservation and continuation as observables."""

import base64
import json
from copy import deepcopy

import pytest
from scapy.all import Ether, IP, TCP, UDP

from ids.config import PreprocessorConfig, load_config
from ids.decoders.decoder import decode_event
from ids.flows.models import FlowAssociation, FlowDirection, TcpState
from ids.models import ApplicationInfo, CaptureSource, ParseError
from ids.pipeline import parse_packet
from ids.preprocessors.preprocessor import preprocess_event
from ids.processing_models import ProcessedEvent
from tests.lab02.test_validation import change_field, make_packet


def run(packet, **settings):
    return preprocess_event(decode_event(packet), PreprocessorConfig(**settings))


@pytest.mark.parametrize("layer", [TCP(flags="S"), TCP(flags="SA"), TCP(flags="A"), UDP()])
def test_empty_transport_packets_are_authorized_without_creating_flows(layer):
    parsed = parse_packet(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / layer, 1, CaptureSource("pcap", "synthetic.pcap"))
    event = run(parsed)
    assert event.preprocess_status == "valid" and event.processing_action == "track"
    assert event.decode_status == "skipped" and event.flow is None


@pytest.mark.parametrize("field", ["application", "payload"])
@pytest.mark.parametrize("policy", ["mark", "skip"])
def test_absent_optional_model_does_not_crash_or_invoke_invalid_policy(field, policy):
    packet = make_packet()
    setattr(packet, field, None)
    raw = packet.to_dict()
    event = run(packet, invalid_event_policy=policy)
    assert event.packet.to_dict() == raw and packet.to_dict() == raw
    assert event.preprocess_status == "partial" and event.processing_action == "track"
    assert event.decode_status == "skipped" and event.reason
    assert not any(error.code.startswith("policy_") for error in event.errors)
    if field == "application":
        assert event.normalized["application"] is None


@pytest.mark.parametrize("field", ["application", "payload"])
@pytest.mark.parametrize("policy, action", [("mark", "track"), ("skip", "skip_tracking")])
def test_wrong_optional_model_type_is_malformed_instead_of_missing(field, policy, action):
    packet = make_packet()
    setattr(packet, field, "wrong-model")
    event = run(packet, invalid_event_policy=policy)
    assert event.preprocess_status == "partial" and event.processing_action == action
    assert "policy_invalid_" + policy in [error.code for error in event.errors]


@pytest.mark.parametrize("missing", [None, "absent"])
def test_missing_dns_lists_have_empty_list_defaults_but_bad_lists_stay_null(missing):
    packet = make_packet()
    packet.transport.protocol = "UDP"
    fields = {} if missing == "absent" else dict.fromkeys(("questions", "answers", "authorities", "additionals"))
    packet.application = ApplicationInfo("DNS", "response", fields)
    event = run(packet)
    assert event.normalized["application"]["fields"] == {
        "questions": [], "answers": [], "authorities": [], "additionals": [],
    }
    assert event.preprocess_status == "valid" and event.processing_action == "track"
    packet.application.fields["answers"] = "wrong-type"
    event = run(packet)
    assert event.normalized["application"]["fields"]["answers"] is None
    assert event.preprocess_status == "partial" and event.processing_action == "skip_tracking"


@pytest.mark.parametrize("protocol, kind", [("HTTP", "response"), ("MIME", "message"), ("SMTP", "message")])
def test_missing_header_dictionary_defaults_to_empty_without_changing_raw(protocol, kind):
    packet = make_packet()
    packet.application = ApplicationInfo(protocol, kind, {"headers": None})
    event = run(packet)
    assert event.normalized["application"]["fields"]["headers"] == {}
    assert event.packet.application.fields["headers"] is None
    assert event.processing_action == "track"


@pytest.mark.parametrize("fields", [{}, {"flags": None}])
def test_missing_tcp_flags_default_to_empty_without_inferring_a_state(fields):
    packet = make_packet()
    packet.transport.fields = fields
    event = run(packet)
    assert event.normalized["transport"]["flags"] == []
    assert event.preprocess_status == "partial" and event.processing_action == "track"
    assert event.flow is None and "state" not in event.normalized["transport"]
    assert [error.code for error in event.errors] == ["validation_missing_tcp_flags"]


@pytest.mark.parametrize("fields", [{}, {"commands": None}, {"commands": []}])
def test_missing_smtp_command_list_does_not_invent_a_command(fields):
    packet = make_packet()
    packet.application = ApplicationInfo("SMTP", "command", fields)
    event = run(packet)
    assert event.normalized["application"]["fields"]["commands"] == []
    assert event.processing_action == "track"


@pytest.mark.parametrize("bad", ["EHLO", {}, 1])
def test_bad_smtp_command_list_is_not_reinterpreted_as_single_command(bad):
    packet = make_packet()
    packet.application = ApplicationInfo("SMTP", "command", {"commands": bad, "command": "EHLO", "domain": "example.com"})
    event = run(packet)
    assert event.normalized["application"]["fields"]["commands"] is None
    assert event.processing_action == "skip_tracking"
    assert "normalization_invalid_smtp_commands" in [error.code for error in event.errors]


@pytest.mark.parametrize("path, value", [
    ("packet_id", True), ("captured_length", -1), ("timestamp", "bad"),
    ("timestamp", "2026-10-09T00:00:00"), ("network", None),
    ("network.src_ip", "bad"), ("transport", None), ("transport.src_port", -1),
    ("transport.dst_port", 65536), ("transport.src_port", True), ("parse_status", "malformed"),
])
@pytest.mark.parametrize("policy", ["mark", "skip"])
def test_invalid_required_metadata_cannot_be_authorized_by_either_policy(path, value, policy):
    packet = make_packet()
    change_field(packet, path, value)
    event = run(packet, invalid_event_policy=policy)
    assert event.preprocess_status == "invalid" and event.processing_action == "skip_tracking"
    assert "policy_invalid_" + policy in [error.code for error in event.errors]
    assert event.reason and event.flow is None


@pytest.mark.parametrize("policy, action", [("mark", "track"), ("skip", "skip_tracking")])
def test_unsupported_application_with_safe_transport_obeys_policy(policy, action):
    packet = make_packet()
    packet.application.protocol = "FTP"
    event = run(packet, unsupported_event_policy=policy)
    assert event.preprocess_status == "partial" and event.processing_action == action
    assert "policy_unsupported_" + policy in [error.code for error in event.errors]


@pytest.mark.parametrize("path, value", [
    ("network.protocol", "ARP"), ("transport.protocol", "SCTP"),
    ("network.fragment_offset", 1), ("parse_status", "unsupported"),
    ("transport.fields", []), ("transport.fields", {"flags": ["BOGUS"]}),
])
@pytest.mark.parametrize("policy", ["mark", "skip"])
def test_unsafe_or_unsupported_transport_never_tracks(path, value, policy):
    packet = make_packet()
    change_field(packet, path, value)
    event = run(packet, invalid_event_policy=policy, unsupported_event_policy=policy)
    assert event.preprocess_status == "partial" and event.processing_action == "skip_tracking"


def test_ipv6_is_preserved_as_unsupported_and_not_authorized_even_with_mark():
    packet = make_packet()
    packet.network.protocol = "IPv6"
    packet.network.src_ip, packet.network.dst_ip = "2001:db8::1", "2001:db8::2"
    event = run(packet, unsupported_event_policy="mark")
    assert event.normalized["network"]["src_ip"] == "2001:db8::1"
    assert event.preprocess_status == "partial" and event.processing_action == "skip_tracking"


@pytest.mark.parametrize("policy, action", [("mark", "track"), ("skip", "skip_tracking")])
def test_bad_optional_data_obeys_invalid_policy_without_changing_status(policy, action):
    packet = make_packet()
    packet.network.ttl = 256
    event = run(packet, invalid_event_policy=policy)
    assert event.preprocess_status == "partial" and event.processing_action == action
    assert event.normalized["network"]["src_ip"] == "10.0.0.1"


@pytest.mark.parametrize("field, limit", [("max_output_bytes", 20), ("max_input_bytes", 10)])
def test_normalization_limit_on_required_metadata_blocks_tracking_even_with_mark(field, limit):
    event = run(make_packet(), invalid_event_policy="mark", **{field: limit})
    assert event.normalized["timestamp"] is None
    assert event.preprocess_status == "partial" and event.processing_action == "skip_tracking"
    assert "policy_unusable_normalized_metadata" in [error.code for error in event.errors]


def test_empty_default_lists_are_checked_against_limits_and_not_restored_after_failure():
    packet = make_packet()
    packet.transport.fields = {}
    event = run(packet, invalid_event_policy="mark", max_output_bytes=1)
    assert event.normalized["transport"]["flags"] is None
    assert event.processing_action == "skip_tracking"


def test_duplicate_flags_are_repaired_without_invoking_invalid_skip_policy():
    packet = make_packet()
    packet.transport.fields["flags"] = ["SYN", "syn"]
    event = run(packet)
    assert event.normalized["transport"]["flags"] == ["SYN"]
    assert event.processing_action == "track" and event.preprocess_status == "partial"


def test_decode_failure_remains_independent_and_preserved_with_safe_metadata():
    packet = make_packet()
    packet.payload.length, packet.payload.base64 = 1, base64.b64encode(b"\xff").decode()
    decoded = decode_event(packet)
    snapshot = deepcopy(decoded.to_dict())
    event = preprocess_event(decoded)
    assert decoded.to_dict() == snapshot
    assert event.decoded == decoded.decoded and event.decode_status == "partial"
    assert event.preprocess_status == "valid" and event.processing_action == "track"
    assert event.errors == decoded.errors and event.reason == decoded.reason


def test_lower_layer_parser_error_blocks_but_application_error_does_not():
    packet = make_packet()
    packet.parse_status = "partial"
    packet.errors = [ParseError("http", "incomplete body")]
    assert run(packet).processing_action == "track"
    packet.errors.append(ParseError("transport", "truncated header"))
    assert run(packet, invalid_event_policy="mark").processing_action == "skip_tracking"


def test_mixed_invalid_and_unsupported_policies_both_apply_without_overriding_skip():
    packet = make_packet()
    packet.network.ttl, packet.application.protocol = 256, "FTP"
    event = run(packet, invalid_event_policy="mark", unsupported_event_policy="skip")
    assert event.processing_action == "skip_tracking"
    assert {error.code for error in event.errors} >= {"policy_invalid_mark", "policy_unsupported_skip"}


def test_reprocessing_replaces_policy_diagnostics_and_recalculates_action():
    packet = make_packet()
    packet.application.protocol = "FTP"
    original = ProcessedEvent(packet, reason="operator note", flow=FlowAssociation("old", FlowDirection.FORWARD, TcpState.NEW))
    snapshot = deepcopy(original.to_dict())
    first = preprocess_event(original, PreprocessorConfig(unsupported_event_policy="skip"))
    assert original.to_dict() == snapshot
    assert preprocess_event(first, PreprocessorConfig(unsupported_event_policy="skip")).to_dict() == first.to_dict()
    second = preprocess_event(first, PreprocessorConfig(unsupported_event_policy="mark"))
    assert second.processing_action == "track" and second.flow is None
    assert "policy_unsupported_skip" not in [error.code for error in second.errors]
    second.packet.application.protocol = "UNKNOWN"
    fixed = preprocess_event(second)
    assert fixed.processing_action == "track" and fixed.errors == [] and fixed.reason == "operator note"
    assert json.loads(json.dumps(fixed.to_dict()))["processing_action"] == "track"


def test_toml_policy_overrides_change_actual_processing(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text('[preprocessor]\ninvalid_event_policy="mark"\nunsupported_event_policy="skip"\n')
    config = load_config(path).preprocessor
    packet = make_packet()
    packet.network.ttl = 256
    assert preprocess_event(decode_event(packet), config).processing_action == "track"
    packet.application.protocol = "FTP"
    assert preprocess_event(decode_event(packet), config).processing_action == "skip_tracking"


def test_bad_packet_model_returns_diagnostics_and_next_packet_continues():
    bad = preprocess_event(decode_event({}))
    assert bad.decode_status == "error" and bad.preprocess_status == "invalid"
    assert bad.processing_action == "skip_tracking" and bad.reason
    assert run(make_packet()).processing_action == "track"
