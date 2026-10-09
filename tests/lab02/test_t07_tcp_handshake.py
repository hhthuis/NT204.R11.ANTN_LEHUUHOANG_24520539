import json

from tests.lab02.reproduce_t07 import EXPECTED, FLOW_ID, reproduce


def test_t07_pcap_handshake_establishes_one_flow_with_empty_payloads(tmp_path):
    events, flows = reproduce(tmp_path)
    saved_events = [json.loads(line) for line in (tmp_path / "actual.jsonl").read_text().splitlines()]
    assert saved_events == events
    assert json.loads((tmp_path / "flows.json").read_text()) == flows == EXPECTED["flows"]
    assert json.loads((tmp_path / "expected.json").read_text()) == EXPECTED
    assert {event["flow"]["flow_id"] for event in saved_events} == {FLOW_ID}
    assert [event["flow"]["state"] for event in saved_events] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]
    assert [event["packet"]["transport"]["fields"]["sequence_number"] for event in events] == [1000, 5000, 1001]
    assert [event["packet"]["transport"]["fields"]["acknowledgment_number"] for event in events] == [0, 1001, 5001]
    assert flows[0]["packet_count"] == 3 and flows[0]["byte_count"] == 162
