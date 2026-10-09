"""T14: malformed/unsupported model events under all mark/skip combinations."""

import argparse
from pathlib import Path

from ids.models import ApplicationInfo, ParseError
from tests.lab02.preprocessor_case_support import make_event, reproduce


PROFILES = {
    "default": {"invalid_event_policy": "skip", "unsupported_event_policy": "mark"},
    "mark-mark": {"invalid_event_policy": "mark", "unsupported_event_policy": "mark"},
    "mark-skip": {"invalid_event_policy": "mark", "unsupported_event_policy": "skip"},
    "skip-skip": {"invalid_event_policy": "skip", "unsupported_event_policy": "skip"},
}

# Independent expectations by scenario: required-invalid and unsafe transport
# can never track; optional malformed/unsupported metadata follows its policy.
ROWS = [
    ("invalid", "invalid-required", ["validation_invalid_ip_address", "normalization_invalid_ip"]),
    ("invalid", "invalid-required", ["validation_invalid_port"]),
    ("invalid", "invalid-required", ["validation_invalid_timestamp", "normalization_invalid_timestamp"]),
    ("invalid", "invalid-required", ["validation_missing_network"]),
    ("invalid", "invalid-required", ["validation_missing_transport"]),
    ("invalid", "invalid-required", ["validation_invalid_port"]),
    ("invalid", "invalid-required", ["validation_malformed_packet"]),
    ("partial", "unsupported-blocked", ["validation_unsupported_network_protocol"]),
    ("partial", "unsupported-blocked", ["validation_unsupported_transport_protocol"]),
    ("partial", "unsupported-optional", ["validation_unsupported_application_protocol"]),
    ("partial", "invalid-optional", ["validation_invalid_ttl"]),
    ("partial", "invalid-optional", ["invalid_percent_encoding", "normalization_invalid_percent_encoding"]),
    ("partial", "invalid-optional", ["normalization_invalid_dns_records"]),
    ("partial", "invalid-blocked", ["validation_invalid_tcp_flags", "normalization_invalid_tcp_flags"]),
    ("partial", "unsupported-blocked", ["validation_unsupported_packet"]),
    ("partial", "unsupported-blocked", ["validation_noninitial_fragment"]),
    ("partial", "invalid-blocked", ["validation_partial_packet", "validation_unsafe_lower_layer_parse"]),
    ("partial", "invalid-optional", ["validation_invalid_application_fields"]),
    ("partial", "invalid-optional", ["invalid_payload_info", "validation_missing_payload_info"]),
    ("partial", "invalid-optional", ["validation_missing_application_info"]),
    ("partial", "both-optional", ["validation_invalid_ttl", "validation_unsupported_application_protocol"]),
    ("partial", "unsupported-optional", ["validation_unsupported_capture_source"]),
    ("valid", "valid", []),
]


def expectations() -> dict:
    expected = {}
    for name, settings in PROFILES.items():
        invalid, unsupported = settings["invalid_event_policy"], settings["unsupported_event_policy"]
        values = []
        for index, (status, category, diagnostics) in enumerate(ROWS):
            codes = list(diagnostics)
            if category.startswith("invalid-") or category == "both-optional":
                codes.append("policy_invalid_" + invalid)
            if category.startswith("unsupported-") or category == "both-optional":
                codes.append("policy_unsupported_" + unsupported)
            allowed = (
                category == "valid"
                or category == "invalid-optional" and invalid == "mark"
                or category == "unsupported-optional" and unsupported == "mark"
                or category == "both-optional" and invalid == unsupported == "mark"
            )
            values.append({"packet_id": index + 1, "status": status,
                           "action": "track" if allowed else "skip_tracking", "error_codes": codes})
        expected[name] = values
    return expected


EXPECTED = expectations()


def fixtures() -> list[dict]:
    packets = [make_event(index + 1) for index in range(23)]
    packets[0].network.src_ip = "not-an-ip"
    packets[1].transport.dst_port = 65536
    packets[2].timestamp = "not-a-timestamp"
    packets[3].network = None
    packets[4].transport = None
    packets[5].transport.src_port = None
    packets[6].parse_status = "malformed"
    packets[7].network.protocol = "IPv6"
    packets[7].network.src_ip, packets[7].network.dst_ip = "2001:db8::1", "2001:db8::2"
    packets[8].transport.protocol = "SCTP"
    packets[9].application.protocol = "FTP"
    packets[10].network.ttl = 256
    packets[11].application = ApplicationInfo("HTTP", "request", {"method": "GET", "target": "/%ZZ", "headers": {}})
    packets[12].application = ApplicationInfo("DNS", "response", {"answers": "wrong-type"})
    packets[13].transport.fields = {"flags": ["BOGUS"]}
    packets[14].parse_status = "unsupported"
    packets[15].network.fragment_offset = 1
    packets[16].parse_status = "partial"
    packets[16].errors = [ParseError("transport", "untrusted transport header")]
    packets[17].application.fields = []
    packets[18].payload = "wrong-model"
    packets[19].application = "wrong-model"
    packets[20].network.ttl = 256
    packets[20].application.protocol = "FTP"
    packets[21].source.type = "unsupported-source"
    return [packet.to_dict() for packet in packets]


def verify_details(outputs: dict[str, list[dict]]) -> None:
    for events in outputs.values():
        assert len(events) == 23
        assert events[0]["normalized"]["network"]["src_ip"] is None
        assert events[1]["normalized"]["transport"]["dst_port"] is None
        assert events[2]["normalized"]["timestamp"] is None
        assert events[3]["normalized"]["network"] is None
        assert events[4]["normalized"]["transport"] is None
        assert events[5]["normalized"]["transport"]["src_port"] is None
        assert events[11]["normalized"]["application"]["fields"]["uri"] is None
        assert events[12]["normalized"]["application"]["fields"]["answers"] is None
        assert events[13]["normalized"]["transport"]["flags"] is None
        assert events[18]["decode_status"] == "error"
        assert all(event["reason"] for event in events[:-1])
        assert events[-1]["processing_action"] == "track" and events[-1]["preprocess_status"] == "valid"
        assert events[-1]["errors"] == [] and events[-1]["reason"] is None
    assert outputs["default"][9]["processing_action"] == "track"
    assert outputs["skip-skip"][9]["processing_action"] == "skip_tracking"
    assert outputs["default"][10]["processing_action"] == "skip_tracking"
    assert outputs["mark-mark"][10]["processing_action"] == "track"
    assert outputs["mark-mark"][20]["processing_action"] == "track"
    assert all(outputs[name][20]["processing_action"] == "skip_tracking" for name in PROFILES if name != "mark-mark")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T14 malformed and unsupported events")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T14")
    directory = parser.parse_args().output_dir
    outputs = reproduce(directory, fixtures(), EXPECTED, PROFILES)
    verify_details(outputs)
    print("T14 PASS: 23 events x 4 policy profiles; unsafe metadata blocked; next valid event processed")


if __name__ == "__main__":
    main()
