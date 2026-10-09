import json

from tests.lab02.preprocessor_case_support import reproduce, summary
from tests.lab02.reproduce_t06 import EXPECTED, PROFILES, fixtures, verify_defaults


def test_t06_missing_optional_fields_survive_full_decoder_preprocessor_pipeline(tmp_path):
    raw = fixtures()
    events = reproduce(tmp_path, raw, EXPECTED, PROFILES)["default"]
    saved = [json.loads(line) for line in (tmp_path / "actual-default.jsonl").read_text().splitlines()]
    assert saved == events and summary(saved) == EXPECTED["default"]
    verify_defaults(saved)
    assert [event["packet"] for event in saved] == raw
    assert "flags" not in saved[3]["packet"]["transport"]["fields"]
    assert "answers" not in saved[5]["packet"]["application"]["fields"]
    assert "headers" not in saved[7]["packet"]["application"]["fields"]
    assert all(event["flow"] is None for event in saved)
