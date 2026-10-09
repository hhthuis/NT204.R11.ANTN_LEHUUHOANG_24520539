import json

import pytest

from tests.lab02.reproduce_t09 import ASSOCIATIONS, EXPECTED, FLOW_ID, ROWS, reproduce_case


@pytest.mark.parametrize("case", ["fin", "rst"])
def test_t09_pcap_close_matches_states_and_complete_flow_summary(case, tmp_path):
    events, flows = reproduce_case(tmp_path, case)
    saved_events = [json.loads(line) for line in (tmp_path / "actual.jsonl").read_text().splitlines()]
    assert saved_events == events
    assert json.loads((tmp_path / "flows.json").read_text()) == flows == EXPECTED[case]["flows"]
    assert json.loads((tmp_path / "expected.json").read_text()) == EXPECTED[case]
    assert {event["flow"]["flow_id"] for event in saved_events} == {FLOW_ID}
    assert [(event["flow"]["direction"], event["flow"]["state"]) for event in events] == ASSOCIATIONS[case]
    assert [event["packet"]["transport"]["fields"]["sequence_number"] for event in events] == [row[2] for row in ROWS[case]]
    assert [event["packet"]["transport"]["fields"]["acknowledgment_number"] for event in events] == [row[3] for row in ROWS[case]]
    assert flows[0]["byte_count"] == sum(event["packet"]["captured_length"] for event in events)
    assert flows[0]["packet_count"] == flows[0]["forward_packet_count"] + flows[0]["backward_packet_count"]
    assert flows[0]["byte_count"] == flows[0]["forward_byte_count"] + flows[0]["backward_byte_count"]
    if case == "fin":
        assert [event["packet"]["transport"]["fields"]["flags"] for event in events[3:]] == [
            ["FIN", "ACK"], ["ACK"], ["FIN", "ACK"], ["ACK"],
        ]
    else:
        assert events[-1]["packet"]["transport"]["fields"]["flags"] == ["RST", "ACK"]
