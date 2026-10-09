"""Reproducible model-boundary cases; this is not a production JSONL reader."""

import json
from pathlib import Path

from ids.config import load_config
from ids.decoders.decoder import decode_event
from ids.models import CaptureSource, NetworkInfo, PacketEvent, TransportInfo
from tests.lab02.event_file_support import packet_from_dict, process_event_file


def make_event(packet_id: int) -> PacketEvent:
    return PacketEvent(
        packet_id=packet_id, timestamp="2026-10-09T00:00:00Z", captured_length=54,
        source=CaptureSource("pcap", "synthetic-parser-event"),
        network=NetworkInfo("IPv4", "10.0.0.1", "10.0.0.2"),
        transport=TransportInfo("TCP", 51000, 8080, {"flags": ["SYN"]}),
    )


def summary(events: list[dict]) -> list[dict]:
    return [
        {"packet_id": event["packet"]["packet_id"], "status": event["preprocess_status"],
         "action": event["processing_action"], "error_codes": [error["code"] for error in event["errors"]]}
        for event in events
    ]


def reproduce(directory: Path, raw: list[dict], expected: dict, profiles: dict) -> dict[str, list[dict]]:
    directory.mkdir(parents=True, exist_ok=True)
    input_path = directory / "input.jsonl"
    input_path.write_text("".join(json.dumps(packet, ensure_ascii=False) + "\n" for packet in raw), encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    outputs = {}
    for name, settings in profiles.items():
        config_path = directory / f"config-{name}.toml"
        config_path.write_text(
            "[preprocessor]\n" + "".join(f'{key} = "{value}"\n' for key, value in settings.items()),
            encoding="utf-8",
        )
        config = load_config(config_path)
        events = process_event_file(input_path, directory / f"actual-{name}.jsonl", config)
        if summary(events) != expected[name]:
            raise AssertionError(f"{name}: status/action/errors do not match the independent expected values")
        if [event["packet"] for event in events] != raw:
            raise AssertionError(f"{name}: raw PacketEvent data changed")
        for source, event in zip(raw, events, strict=True):
            decoded = decode_event(packet_from_dict(source), config.decoder).to_dict()
            if event["decoded"] != decoded["decoded"] or event["decode_status"] != decoded["decode_status"]:
                raise AssertionError(f"{name}: decoder output changed")
            if event["flow"] is not None:
                raise AssertionError("Preprocessor authorization must not create flows")
            if event["errors"] and not event["reason"]:
                raise AssertionError("Event diagnostics require a reason")
        outputs[name] = events
        print(f"{name}: {len(events)} events match expected; raw/decoded retained")
    return outputs
