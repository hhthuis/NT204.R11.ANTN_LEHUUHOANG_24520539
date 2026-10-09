import json

from tests.lab02.preprocessor_case_support import reproduce, summary
from tests.lab02.reproduce_t14 import EXPECTED, PROFILES, fixtures, verify_details


def test_t14_malformed_and_unsupported_events_obey_all_policy_combinations_and_continue(tmp_path):
    raw = fixtures()
    outputs = reproduce(tmp_path, raw, EXPECTED, PROFILES)
    verify_details(outputs)
    for name, events in outputs.items():
        saved = [json.loads(line) for line in (tmp_path / f"actual-{name}.jsonl").read_text().splitlines()]
        assert saved == events and summary(saved) == EXPECTED[name]
        assert [event["packet"] for event in saved] == raw
        assert all(event["flow"] is None for event in saved)
        # Required invalid and transport-unsafe cases remain blocked with mark.
        for index in (0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16):
            assert saved[index]["processing_action"] == "skip_tracking"
    assert outputs["mark-mark"][11]["errors"][0]["stage"] == "decode"
    assert outputs["mark-mark"][11]["errors"][1]["stage"] == "preprocess"
