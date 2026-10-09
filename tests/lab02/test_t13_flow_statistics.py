import json

from tests.lab02.reproduce_t13 import EXPECTED, TCP_ID, UDP_ID, reproduce, verify_details


def test_t13_pcap_statistics_match_exact_byte_flag_direction_time_and_application_expectations(tmp_path):
    events, flows = reproduce(tmp_path)
    saved_events = [json.loads(line) for line in (tmp_path / "actual.jsonl").read_text().splitlines()]
    saved_flows = json.loads((tmp_path / "flows.json").read_text())
    assert saved_events == events and saved_flows == flows == EXPECTED["flows"]
    verify_details(saved_events, saved_flows)
    tcp, udp = {flow["flow_id"]: flow for flow in flows}[TCP_ID], {flow["flow_id"]: flow for flow in flows}[UDP_ID]
    assert tcp["application_protocol"] == "HTTP" and udp["application_protocol"] == "UNKNOWN"
    assert events[0]["packet"]["application"]["protocol"] == "UNKNOWN"
    assert events[5]["flow"]["direction"] == "backward"  # oldest TCP timestamp does not redefine A
    assert events[11]["flow"]["direction"] == "backward"  # oldest UDP timestamp does not redefine A
    assert events[-1]["flow"]["flow_id"] == UDP_ID  # continues after skipped packet
    assert (tcp["syn_count"], tcp["ack_count"], tcp["fin_count"], tcp["rst_count"]) == (2, 8, 1, 1)
    assert all(udp[name] == 0 for name in ("syn_count", "ack_count", "fin_count", "rst_count"))
