import json

from tests.lab02.reproduce_task17_cli import CASES, read_rows, reproduce


def test_existing_lab_pcaps_run_through_executable_and_produce_complete_flow_outputs(tmp_path):
    report = reproduce(tmp_path)
    assert [entry["case"] for entry in report] == list(CASES)
    assert json.loads((tmp_path / "cases.json").read_text()) == report
    assert all(entry["exit_code"] == 0 and entry["status"] == "PASS" for entry in report)
    for entry in report:
        assert len(read_rows(tmp_path / entry["events"])) == entry["packet_count"]
        assert len(read_rows(tmp_path / entry["flows"])) == entry["flow_count"]
