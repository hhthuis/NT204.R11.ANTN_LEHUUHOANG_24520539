import base64
import json

import pytest

from ids.config import DecoderConfig
from tests.lab02.reproduce_t04 import RAW_PAYLOADS, decode_pcap, generate_input_pcap


@pytest.mark.parametrize("policy, first_status, first_text", [
    ("replace", "partial", "bad utf8: \ufffd\r\n"),
    ("strict", "error", None),
])
def test_t04_invalid_packet_does_not_stop_next_packet(
    tmp_path, policy, first_status, first_text
):
    input_path = tmp_path / "input.pcap"
    output_path = tmp_path / "actual.jsonl"
    generate_input_pcap(input_path)

    decode_pcap(input_path, output_path, DecoderConfig(invalid_bytes_policy=policy))
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert len(events) == 2
    first, second = events
    assert first["decode_status"] == first_status
    assert first["decoded"]["payload"]["text"] == first_text
    assert first["decoded"]["payload"]["charset"] == "utf-8"
    assert first["reason"]
    assert first["errors"][0]["stage"] == "decode"
    assert first["errors"][0]["code"] == "invalid_character_sequence"
    assert second["decode_status"] == "ok"
    assert second["decoded"]["payload"]["text"] == "next valid event\r\n"
    assert second["errors"] == []
    assert second["reason"] is None
    for packet_id, (saved, raw) in enumerate(zip(events, RAW_PAYLOADS, strict=True), 1):
        packet = saved["packet"]
        assert packet["packet_id"] == packet_id
        assert packet["source"] == {"type": "pcap", "name": "input.pcap"}
        assert packet["parse_status"] == "ok"
        assert packet["transport"]["protocol"] == "TCP"
        assert base64.b64decode(packet["payload"]["base64"]) == raw
        assert packet["payload"]["length"] == len(raw)
        assert saved["processing_action"] == "skip_tracking"
        assert saved["preprocess_status"] is None
        assert saved["flow"] is None
