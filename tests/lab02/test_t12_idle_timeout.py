import json

from tests.lab02.reproduce_t12 import EXPECTED, reproduce


def test_t12_expiry_cleans_table_context_and_new_lifetime_has_fresh_statistics(tmp_path):
    events, summaries = reproduce(tmp_path)
    assert json.loads((tmp_path / "checkpoints.json").read_text()) == EXPECTED
    assert [json.loads(row) for row in (tmp_path / "actual.jsonl").read_text().splitlines()] == events
    assert [json.loads(row) for row in (tmp_path / "flows.jsonl").read_text().splitlines()] == summaries
    assert all(event["errors"] == [] and event["flow"]["direction"] == "forward" for event in events)
    assert [event["packet"]["captured_length"] for event in events] == [54, 42, 54, 42]
    assert sum(summary["byte_count"] for summary in summaries) == 192
    assert events[1]["flow"]["flow_id"] != events[3]["flow"]["flow_id"]
