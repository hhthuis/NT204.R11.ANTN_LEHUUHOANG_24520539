import json

from tests.lab02.reproduce_t11 import ASSOCIATIONS, EXPECTED, FLOW_IDS, reproduce


def test_t11_interleaved_pcap_flows_stay_separate_and_skipped_packet_does_not_add_flow(tmp_path):
    events, flows = reproduce(tmp_path)
    saved = [json.loads(line) for line in (tmp_path / "actual.jsonl").read_text().splitlines()]
    assert saved == events
    assert json.loads((tmp_path / "flows.json").read_text()) == flows == EXPECTED["flows"]
    assert len(flows) == len({flow["flow_id"] for flow in flows}) == 6
    for event, (label, direction) in zip(saved, ASSOCIATIONS, strict=True):
        if label:
            assert event["flow"]["flow_id"] == FLOW_IDS[label]
            assert event["flow"]["direction"] == direction
        else:
            assert event["flow"] is None and event["processing_action"] == "skip_tracking"
    assert saved[0]["flow"]["flow_id"] != saved[3]["flow"]["flow_id"]  # same endpoint pair, TCP vs UDP
    assert saved[0]["flow"]["flow_id"] != saved[1]["flow"]["flow_id"]  # source port differs
    assert saved[0]["flow"]["flow_id"] != saved[2]["flow"]["flow_id"]  # destination IP differs
    assert saved[0]["flow"]["flow_id"] != saved[4]["flow"]["flow_id"]  # destination port differs
    assert saved[0]["flow"]["flow_id"] != saved[5]["flow"]["flow_id"]  # source IP differs
    assert saved[12]["packet"]["parse_status"] == "unsupported" and saved[12]["reason"]
    assert saved[13]["flow"]["flow_id"] == saved[0]["flow"]["flow_id"]
    assert saved[14]["flow"]["flow_id"] == saved[3]["flow"]["flow_id"]
    assert saved[-1]["flow"]["flow_id"] == saved[1]["flow"]["flow_id"]
