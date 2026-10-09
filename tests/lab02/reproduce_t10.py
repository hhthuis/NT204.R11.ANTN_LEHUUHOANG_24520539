"""T10: DNS A query and response share one UDP flow, with exact wire statistics."""

import argparse
import json
from pathlib import Path

from scapy.all import wrpcap

from ids.config import load_config
from tests.lab02.flow_pcap_support import summarize, track_pcap
from tests.lab02.udp_dns_support import make_dns_packet


FLOW_ID = "flow-b9c4049d557c4aef63cdf8b3c0ba566852aa046982c9b92773f21373c6c45efa"
QUESTION = {"name": "Example.Test", "type": "A", "type_code": 1, "class": "IN", "class_code": 1}
ANSWER = {"name": "Example.Test", "type": "A", "type_code": 1, "class": "IN", "class_code": 1,
          "ttl": 300, "data": "192.0.2.10"}
RESPONSE_DIAGNOSTIC = {
    "stage": "decode", "code": "invalid_character_sequence",
    "message": "Invalid utf-8 sequence at bytes 2:3: invalid start byte",
}
EXPECTED = {
    "events": [
        {"packet_id": 1, "action": "track", "status": "valid",
         "flow": {"flow_id": FLOW_ID, "direction": "forward", "state": None}},
        {"packet_id": 2, "action": "track", "status": "valid",
         "flow": {"flow_id": FLOW_ID, "direction": "backward", "state": None}},
    ],
    "flows": [{
        "flow_id": FLOW_ID, "protocol": "UDP", "application_protocol": "DNS",
        "endpoint_a": {"ip": "10.0.0.2", "port": 53000},
        "endpoint_b": {"ip": "10.0.0.1", "port": 53},
        "start_time": "2026-10-09T00:00:00.000000Z",
        "last_seen": "2026-10-09T00:00:00.200000Z", "duration": 0.2,
        "state": None, "packet_count": 2, "byte_count": 172,
        "forward_packet_count": 1, "forward_byte_count": 72,
        "backward_packet_count": 1, "backward_byte_count": 100,
        "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
    }],
    "dns": [
        {"protocol": "DNS", "kind": kind, "transaction_id": 0x1234,
         "response_code": "NOERROR",
         "counts": {"question": 1, "answer": int(kind == "response"), "authority": 0, "additional": 0},
         "raw_questions": [QUESTION], "raw_answers": [ANSWER] if kind == "response" else [],
         "normalized_questions": [{**QUESTION, "name": "example.test"}],
         "normalized_answers": [{**ANSWER, "name": "example.test"}] if kind == "response" else []}
        for kind in ("query", "response")
    ],
    "diagnostics": [
        {"parse_status": "ok", "decode_status": "ok", "errors": [], "reason": None},
        {"parse_status": "ok", "decode_status": "partial", "errors": [RESPONSE_DIAGNOSTIC],
         "reason": RESPONSE_DIAGNOSTIC["message"]},
    ],
}


def dns_views(events: list[dict]) -> list[dict]:
    views = []
    for event in events:
        app = event["packet"]["application"]
        raw, normalized = app["fields"], event["normalized"]["application"]["fields"]
        views.append({
            "protocol": app["protocol"], "kind": app["kind"],
            "transaction_id": raw["transaction_id"], "response_code": raw["response_code"], "counts": raw["counts"],
            "raw_questions": raw["questions"], "raw_answers": raw["answers"],
            "normalized_questions": normalized["questions"], "normalized_answers": normalized["answers"],
        })
    return views


def diagnostics(events: list[dict]) -> list[dict]:
    return [{"parse_status": event["packet"]["parse_status"], "decode_status": event["decode_status"],
             "errors": event["errors"], "reason": event["reason"]} for event in events]


def reproduce(directory: Path) -> tuple[list[dict], list[dict]]:
    directory.mkdir(parents=True, exist_ok=True)
    input_path = directory / "input.pcap"
    wrpcap(str(input_path), [make_dns_packet(), make_dns_packet(response=True, offset="0.2")])
    default_config = Path(__file__).resolve().parents[2] / "config/default.toml"
    config_path = directory / "config.toml"
    config_path.write_text(default_config.read_text(), encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n", encoding="utf-8")
    events, flows = track_pcap(input_path, directory / "actual.jsonl", directory / "flows.json", load_config(config_path))
    actual = {"events": summarize(events), "flows": flows, "dns": dns_views(events), "diagnostics": diagnostics(events)}
    if actual != EXPECTED:
        raise AssertionError("T10 DNS fields/flow identity/direction/statistics/diagnostics do not match independent expectations")
    assert [event["packet"]["captured_length"] for event in events] == [72, 100]
    assert [event["packet"]["payload"]["length"] for event in events] == [30, 58]
    for event in events:
        assert event["packet"]["errors"] == []
        assert event["packet"]["application"]["fields"]["message_complete"] is True
        assert event["normalized"]["transport"]["flags"] is None
        for section in ("authorities", "additionals"):
            assert event["normalized"]["application"]["fields"][section] == []
    return events, flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce T10 DNS UDP query/response")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "TEST/lab02/T10")
    events, flows = reproduce(parser.parse_args().output_dir)
    for event in events:
        print(f"packet {event['packet']['packet_id']}: DNS {event['packet']['application']['kind']}; "
              f"{event['flow']['direction']}; bytes={event['packet']['captured_length']}; decode={event['decode_status']}")
    flow = flows[0]
    print(f"T10 PASS: 1 UDP/DNS flow, state=null; packets={flow['packet_count']}, bytes={flow['byte_count']}; "
          f"forward=1/72, backward=1/100, duration={flow['duration']}; binary text diagnostic preserved")


if __name__ == "__main__":
    main()
