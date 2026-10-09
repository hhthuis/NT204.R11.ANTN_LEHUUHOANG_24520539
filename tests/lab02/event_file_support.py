"""Read synthetic PacketEvent JSONL fixtures and run decoder/preprocessor APIs."""

import json
from pathlib import Path

from ids.config import ProcessingConfig
from ids.decoders.decoder import decode_event
from ids.models import ApplicationInfo, CaptureSource, NetworkInfo, PacketEvent, ParseError, PayloadInfo, TransportInfo
from ids.preprocessors.preprocessor import preprocess_event


def packet_from_dict(value: dict) -> PacketEvent:
    fields = dict(value)
    for name, model in (
        ("source", CaptureSource), ("network", NetworkInfo), ("transport", TransportInfo),
        ("application", ApplicationInfo), ("payload", PayloadInfo),
    ):
        if isinstance(fields.get(name), dict):
            fields[name] = model(**fields[name])
    if "errors" in fields:
        fields["errors"] = [ParseError(**error) for error in fields["errors"]]
    return PacketEvent(**fields)


def process_event_file(input_path: Path, output_path: Path, config: ProcessingConfig) -> list[dict]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    events = []
    with input_path.open(encoding="utf-8") as source, output_path.open("w", encoding="utf-8") as output:
        for line in source:
            if not line.strip():
                continue
            packet = packet_from_dict(json.loads(line))
            event = preprocess_event(decode_event(packet, config.decoder), config.preprocessor).to_dict()
            output.write(json.dumps(event, ensure_ascii=False) + "\n")
            events.append(event)
    return events
