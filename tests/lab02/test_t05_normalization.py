import json

from ids.config import load_config
from ids.decoders.decoder import decode_event
from tests.lab02.event_file_support import packet_from_dict, process_event_file
from tests.lab02.reproduce_t05 import EXPECTED, summarize, write_input


def test_t05_equivalent_event_formats_normalize_consistently_and_keep_raw(tmp_path):
    input_path = tmp_path / "input.jsonl"
    output_path = tmp_path / "actual.jsonl"
    raw = write_input(input_path)
    events = process_event_file(input_path, output_path, load_config())
    saved = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert saved == events and len(events) == 10
    assert summarize(events) == EXPECTED
    assert [event["packet"] for event in events] == raw
    for source, event in zip(raw, events, strict=True):
        decoded = decode_event(packet_from_dict(source))
        assert event["decoded"] == decoded.to_dict()["decoded"]
        assert event["decode_status"] == decoded.decode_status
        assert event["processing_action"] == ("skip_tracking" if event["preprocess_status"] == "invalid" else "track")
        assert event["flow"] is None
        if event["errors"]:
            assert event["reason"] and all(error["stage"] == "preprocess" for error in event["errors"])
        else:
            assert event["reason"] is None
    for first in (0, 2, 4, 6):
        assert events[first]["normalized"] == events[first + 1]["normalized"]
        assert events[first]["packet"] != events[first + 1]["packet"]
    assert events[0]["normalized"]["application"]["fields"]["uri"]["path"] == "/Admin%2FA"
    assert events[0]["decoded"]["http"]["uri"]["text"] == "/Admin/A?q=x+y&x=%2f"
    assert events[0]["normalized"]["application"]["fields"]["headers"]["x-token"] == ["AbC", "DeF"]
    assert events[6]["normalized"]["application"]["fields"]["commands"][0]["mailbox"] == "Alice@example.com"
    assert events[8]["preprocess_status"] == "invalid" and events[8]["normalized"]["timestamp"] is None
    assert events[9]["preprocess_status"] == "valid"
