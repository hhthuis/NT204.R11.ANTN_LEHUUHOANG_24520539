"""T06: optional missing fields get consistent defaults without exceptions."""

import argparse
from pathlib import Path

from ids.models import ApplicationInfo
from tests.lab02.preprocessor_case_support import make_event, reproduce


PROFILES = {"default": {"invalid_event_policy": "skip", "unsupported_event_policy": "mark"}}
EXPECTED = {"default": [
    {"packet_id": index + 1, "status": "partial" if index in (1, 2, 3, 4) else "valid",
     "action": "track", "error_codes": {
         1: ["validation_missing_application_info"], 2: ["validation_missing_payload_info"],
         3: ["validation_missing_tcp_flags"], 4: ["validation_missing_tcp_flags"],
     }.get(index, [])}
    for index in range(11)
]}


def fixtures() -> list[dict]:
    packets = [make_event(index + 1) for index in range(11)]
    packets[1].application = None
    packets[2].payload = None
    packets[3].transport.fields = {}
    packets[4].transport.fields = {"flags": None}
    for index in (5, 6):
        packets[index].transport.protocol = "UDP"
        packets[index].transport.dst_port = 53
    packets[5].application = ApplicationInfo("DNS", "query", {
        "questions": [{"name": "Example.COM.", "type": "A", "class": "IN"}],
    })
    packets[6].application = ApplicationInfo("DNS", "response", {
        "questions": None, "answers": None, "authorities": None, "additionals": None,
    })
    packets[7].application = ApplicationInfo("HTTP", "response", {})
    packets[8].application = ApplicationInfo("SMTP", "command", {})
    packets[9].application = ApplicationInfo("SMTP", "command", {"commands": None})
    return [packet.to_dict() for packet in packets]


def verify_defaults(events: list[dict]) -> None:
    assert events[0]["normalized"]["application"]["kind"] is None
    assert events[1]["normalized"]["application"] is None
    assert events[2]["decode_status"] == "skipped" and events[2]["packet"]["payload"] is None
    for index in (3, 4):
        assert events[index]["normalized"]["transport"]["flags"] == []
        assert "state" not in events[index]["normalized"]["transport"]
    dns = events[5]["normalized"]["application"]["fields"]
    assert dns == {"questions": [{"name": "example.com", "type": "A", "class": "IN"}],
                   "answers": [], "authorities": [], "additionals": []}
    assert events[6]["normalized"]["application"]["fields"] == dict.fromkeys(
        ("questions", "answers", "authorities", "additionals"), [],
    )
    assert events[7]["normalized"]["application"]["fields"]["headers"] == {}
    for index in (8, 9):
        assert events[index]["normalized"]["application"]["fields"]["commands"] == []
    for event in events:
        assert event["normalized"]["network"]["src_ip"] == "10.0.0.1"
        assert event["normalized"]["timestamp"] == "2026-10-09T00:00:00.000000Z"
    assert events[-1]["preprocess_status"] == "valid" and events[-1]["processing_action"] == "track"


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T06 optional missing fields")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T06")
    directory = parser.parse_args().output_dir
    events = reproduce(directory, fixtures(), EXPECTED, PROFILES)["default"]
    verify_defaults(events)
    print(f"T06 PASS: {len(events)} events; null/[]/{{}} defaults checked; next valid event processed")


if __name__ == "__main__":
    main()
