import json

from tests.lab02.reproduce_t08 import EXPECTED, FLOW_ID, reproduce


def test_t08_pcap_packets_share_bidirectional_identity_with_correct_direction(tmp_path):
    events, flows = reproduce(tmp_path)
    saved_events = [json.loads(line) for line in (tmp_path / "actual.jsonl").read_text().splitlines()]
    assert saved_events == events
    assert json.loads((tmp_path / "flows.json").read_text()) == flows == EXPECTED["flows"]
    assert len(flows) == 1 and {event["flow"]["flow_id"] for event in events} == {FLOW_ID}
    assert [event["flow"]["direction"] for event in events] == ["forward", "backward", "forward", "backward", "forward"]
    assert flows[0]["endpoint_a"]["ip"] == "10.0.0.2" and flows[0]["endpoint_b"]["ip"] == "10.0.0.1"
    assert all(event["packet"]["payload"]["length"] == 0 for event in events)
    assert all(event["packet"]["transport"]["fields"]["flags"] == ["ACK"] for event in events)
    assert all(event["flow"]["state"] == "NEW" for event in events)
