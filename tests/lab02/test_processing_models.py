import base64
import json

from ids.models import ApplicationInfo, CaptureSource, PacketEvent, PayloadInfo
from ids.processing_models import (
    DecodeStatus,
    PreprocessStatus,
    ProcessedEvent,
    ProcessingAction,
    ProcessingError,
    ProcessingStage,
)


def make_packet() -> PacketEvent:
    payload = b"GET /search?q=%27%20OR%201%3D1 HTTP/1.1\r\n\r\n\xff"
    return PacketEvent(
        packet_id=1,
        timestamp="2026-10-09T00:00:00Z",
        source=CaptureSource(type="pcap", name="test.pcap"),
        captured_length=len(payload),
        application=ApplicationInfo(
            protocol="HTTP",
            kind="request",
            fields={"target": "/search?q=%27%20OR%201%3D1"},
        ),
        payload=PayloadInfo(
            length=len(payload),
            base64=base64.b64encode(payload).decode("ascii"),
        ),
    )


def test_unprocessed_event_serializes_missing_data_without_authorizing_tracking():
    event = ProcessedEvent(packet=make_packet())

    saved = json.loads(json.dumps(event.to_dict()))

    assert saved["packet"]["network"] is None
    assert saved["packet"]["transport"] is None
    assert saved["decoded"] == {}
    assert saved["normalized"] == {}
    assert saved["decode_status"] == "skipped"
    assert saved["preprocess_status"] is None
    assert saved["processing_action"] == "skip_tracking"
    assert saved["reason"] is None
    assert saved["flow"] is None
    assert saved["errors"] == []


def test_processed_fields_and_errors_round_trip_without_losing_raw_bytes():
    packet = make_packet()
    original = packet.to_dict()
    event = ProcessedEvent(
        packet=packet,
        decoded={"uri": "/search?q=' OR 1=1", "text": "Tiếng Việt"},
        normalized={"protocol": "HTTP", "optional_fields": []},
        decode_status=DecodeStatus.PARTIAL,
        preprocess_status=PreprocessStatus.PARTIAL,
        processing_action=ProcessingAction.SKIP_TRACKING,
        reason="Missing transport endpoints",
        errors=[
            ProcessingError(
                stage=ProcessingStage.DECODE,
                code="invalid_character_sequence",
                message="Payload contains an invalid UTF-8 byte",
            )
        ],
    )

    saved = json.loads(json.dumps(event.to_dict(), ensure_ascii=False))

    assert packet.to_dict() == original
    assert saved["packet"] == original
    assert saved["packet"]["application"]["fields"]["target"] == (
        "/search?q=%27%20OR%201%3D1"
    )
    assert base64.b64decode(saved["packet"]["payload"]["base64"]).endswith(
        b"\xff"
    )
    assert saved["decoded"]["uri"] == "/search?q=' OR 1=1"
    assert saved["decoded"]["text"] == "Tiếng Việt"
    assert saved["normalized"]["optional_fields"] == []
    assert saved["decode_status"] == "partial"
    assert saved["preprocess_status"] == "partial"
    assert saved["errors"][0]["stage"] == "decode"
    assert saved["errors"][0]["code"] == "invalid_character_sequence"


def test_packet_snapshots_and_mutable_defaults_are_isolated_between_events():
    packet = make_packet()
    first = ProcessedEvent(packet=packet)
    second = ProcessedEvent(packet=packet)

    first.packet.application.fields["target"] = "/changed"
    first.packet.source.name = "changed.pcap"
    first.decoded["uri"] = "/changed"
    first.normalized["protocol"] = "HTTP"
    first.errors.append(
        ProcessingError(
            stage=ProcessingStage.PREPROCESS,
            code="missing_field",
            message="Missing destination IP",
        )
    )

    assert packet.application.fields["target"] == "/search?q=%27%20OR%201%3D1"
    assert packet.source.name == "test.pcap"
    assert second.packet.to_dict() == packet.to_dict()
    assert second.decoded == {}
    assert second.normalized == {}
    assert second.errors == []


def test_serialized_output_does_not_share_nested_state_with_event():
    event = ProcessedEvent(
        packet=make_packet(),
        decoded={"form": {"query": ["original"]}},
    )

    exported = event.to_dict()
    exported["packet"]["application"]["fields"]["target"] = "/changed"
    exported["decoded"]["form"]["query"].append("changed")

    assert event.packet.application.fields["target"] == (
        "/search?q=%27%20OR%201%3D1"
    )
    assert event.decoded["form"]["query"] == ["original"]
