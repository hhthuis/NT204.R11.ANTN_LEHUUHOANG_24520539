import json
import sys
from pathlib import Path

import pytest
from scapy.all import Ether, IP, Raw, UDP, wrpcap
from scapy.error import Scapy_Exception

from ids import cli
from ids.config import ProcessingConfig, TrackerConfig
from tests.lab02.reproduce_t12 import BASE, generate_input_pcap
from tests.lab02.udp_dns_support import make_dns_packet


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_processed_pcap_writes_nested_events_and_one_final_dns_summary(tmp_path):
    source, events, flows = [tmp_path / name for name in ("input.pcap", "events.jsonl", "flows.jsonl")]
    wrpcap(str(source), [make_dns_packet(), make_dns_packet(response=True, offset="0.2")])
    result = cli.run_processed_pcap(source, events, flows)
    saved, summaries = rows(events), rows(flows)
    assert result.packet_count == 2 and result.flow_count == 1 and not result.stopped
    assert [event["packet"]["packet_id"] for event in saved] == [1, 2]
    assert {event["flow"]["flow_id"] for event in saved} == {summaries[0]["flow_id"]}
    assert summaries[0]["packet_count"] == 2 and summaries[0]["byte_count"] == 172
    assert summaries[0]["end_reason"] == "capture_eof" and summaries[0]["duration"] == 0.2
    assert summaries[0]["end_time"] == "2026-10-09T00:00:00.200000Z"
    assert saved[1]["decode_status"] == "partial" and saved[1]["preprocess_status"] == "valid"


def test_main_processed_config_controls_decoder_capacity_and_outputs(tmp_path, monkeypatch, capsys):
    source, events, flows, config = [tmp_path / name for name in ("input.pcap", "events", "flows", "config.toml")]
    packets = [make_dns_packet(payload=b"\xff", client_port=port) for port in (53000, 53001)]
    wrpcap(str(source), packets)
    config.write_text('[decoder]\ninvalid_bytes_policy="strict"\n[tracker]\nmax_active_flows=1\ncapacity_policy="skip_new"\n')
    monkeypatch.setattr(sys, "argv", ["main.py", "--mode", "processed", "--pcap", str(source), "--config", str(config), "--output", str(events), "--flows-output", str(flows)])
    assert cli.main() == 0
    saved, summaries = rows(events), rows(flows)
    assert saved[0]["decode_status"] == "error"
    assert saved[1]["processing_action"] == "skip_tracking" and saved[1]["errors"][-1]["code"] == "tracker_flow_capacity"
    assert len(summaries) == 1 and summaries[0]["packet_count"] == 1
    assert "2 packets, wrote 1 flow summaries" in capsys.readouterr().out


def test_processed_pcap_idle_expiry_outputs_old_and_new_lifetimes_once(tmp_path):
    source, events, flows = [tmp_path / name for name in ("input.pcap", "events", "flows")]
    generate_input_pcap(source)
    config = ProcessingConfig(tracker=TrackerConfig(tcp_idle_timeout=3, udp_idle_timeout=2, max_pending_summaries=1))
    result = cli.run_processed_pcap(source, events, flows, config)
    summaries = rows(flows)
    assert result.packet_count == 4 and result.flow_count == 3
    assert len({summary["flow_id"] for summary in summaries}) == 3
    assert [summary["end_reason"] for summary in summaries] == ["idle_timeout", "idle_timeout", "capture_eof"]
    assert sum(summary["packet_count"] for summary in summaries) == 4
    assert sum(summary["byte_count"] for summary in summaries) == 192
    assert rows(events)[1]["flow"]["flow_id"] != rows(events)[3]["flow"]["flow_id"]


def test_empty_pcap_creates_empty_outputs(tmp_path):
    source, events, flows = [tmp_path / name for name in ("empty.pcap", "events", "flows")]
    wrpcap(str(source), [])
    result = cli.run_processed_pcap(source, events, flows)
    assert result.packet_count == result.flow_count == 0
    assert events.read_text() == flows.read_text() == ""


@pytest.mark.parametrize("missing", [False, True])
def test_bad_or_missing_pcap_does_not_truncate_outputs(tmp_path, missing):
    source, events, flows = [tmp_path / name for name in ("input.pcap", "events", "flows")]
    if not missing:
        source.write_text("not a pcap")
    events.write_text("preserve events")
    flows.write_text("preserve flows")
    with pytest.raises((OSError, Scapy_Exception)):
        cli.run_processed_pcap(source, events, flows)
    assert events.read_text() == "preserve events" and flows.read_text() == "preserve flows"


@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink", "outputs", "config", "directory"])
def test_cli_rejects_output_collisions_before_truncating_inputs(tmp_path, alias, monkeypatch):
    source, events, flows, config = [tmp_path / name for name in ("input.pcap", "events", "flows", "config.toml")]
    wrpcap(str(source), [make_dns_packet()])
    original = source.read_bytes()
    config.write_text("[tracker]\nmax_active_flows=10\n")
    original_config = config.read_text()
    if alias == "same":
        events = source
    elif alias == "symlink":
        events.symlink_to(source)
    elif alias == "hardlink":
        events.hardlink_to(source)
    elif alias == "outputs":
        flows = events
    elif alias == "config":
        events = config
    else:
        events.mkdir()
    monkeypatch.setattr(sys, "argv", ["main.py", "--mode", "processed", "--pcap", str(source), "--config", str(config), "--output", str(events), "--flows-output", str(flows)])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2 and source.read_bytes() == original and config.read_text() == original_config


def test_bad_config_is_reported_before_opening_outputs(tmp_path, monkeypatch):
    events, flows, config = [tmp_path / name for name in ("events", "flows", "config.toml")]
    events.write_text("keep")
    flows.write_text("keep")
    config.write_text("[invalid]\nvalue=1")
    monkeypatch.setattr(sys, "argv", ["main.py", "--mode", "processed", "--pcap", "missing", "--config", str(config), "--output", str(events), "--flows-output", str(flows)])
    with pytest.raises(SystemExit):
        cli.main()
    assert events.read_text() == flows.read_text() == "keep"


@pytest.mark.parametrize("flag", ["--config", "--flows-output"])
def test_parser_mode_refuses_processed_only_flags(flag, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--pcap", "missing", flag, "value"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


def test_default_parser_mode_preserves_flat_packet_schema(tmp_path, monkeypatch):
    source, events = tmp_path / "input.pcap", tmp_path / "events"
    wrpcap(str(source), [make_dns_packet()])
    monkeypatch.setattr(sys, "argv", ["main.py", "--pcap", str(source), "--output", str(events)])
    assert cli.main() == 0
    assert "packet_id" in rows(events)[0] and "normalized" not in rows(events)[0]


@pytest.mark.parametrize("policy, action", [("mark", "track"), ("skip", "skip_tracking")])
def test_cli_preprocessor_config_changes_invalid_uri_tracking_policy(tmp_path, monkeypatch, policy, action):
    from scapy.all import TCP

    source, events, flows, config = [tmp_path / name for name in ("input.pcap", "events", "flows", "config.toml")]
    packet = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=51000, dport=8080, flags="PA") / Raw(b"GET /bad%ZZ HTTP/1.1\r\nHost: Example.Test\r\n\r\n")
    packet.time = BASE.timestamp()
    wrpcap(str(source), [packet])
    config.write_text(f'[preprocessor]\ninvalid_event_policy="{policy}"\n')
    monkeypatch.setattr(sys, "argv", ["main.py", "--mode", "processed", "--pcap", str(source), "--config", str(config), "--output", str(events), "--flows-output", str(flows)])
    assert cli.main() == 0
    assert rows(events)[0]["processing_action"] == action and rows(events)[0]["reason"]
    assert len(rows(flows)) == int(action == "track")


def test_pcap_eof_preserves_established_state_without_inventing_fin(tmp_path):
    source = Path(__file__).resolve().parents[2] / "TEST/lab02/T07/input.pcap"
    events, flows = tmp_path / "events", tmp_path / "flows"
    result = cli.run_processed_pcap(source, events, flows)
    assert result.packet_count == 3 and result.flow_count == 1
    assert [event["flow"]["state"] for event in rows(events)] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]
    assert rows(flows)[0]["state"] == "ESTABLISHED" and rows(flows)[0]["end_reason"] == "capture_eof"
    assert rows(flows)[0]["fin_count"] == rows(flows)[0]["rst_count"] == 0


def test_pcap_interrupt_finalizes_flows_and_closes_reader(tmp_path, monkeypatch):
    closed = []

    def packets(path):
        try:
            yield make_dns_packet()
            raise KeyboardInterrupt
        finally:
            closed.append(True)

    monkeypatch.setattr(cli, "read_pcap", packets)
    events, flows = tmp_path / "events", tmp_path / "flows"
    result = cli.run_processed_pcap(tmp_path / "mock.pcap", events, flows)
    assert result.stopped and result.packet_count == 1 and closed == [True]
    assert rows(flows)[0]["end_reason"] == "capture_stopped"


def test_main_reports_capture_permission_error_with_failure_exit(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "validate_interface", lambda interface: None)

    def fail(**kwargs):
        raise PermissionError("raw socket permission denied")

    monkeypatch.setattr(cli, "capture_live_periodic", fail)
    monkeypatch.setattr(sys, "argv", ["main.py", "--mode", "processed", "--interface", "mock0", "--output", str(tmp_path / "events"), "--flows-output", str(tmp_path / "flows")])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2 and "permission denied" in capsys.readouterr().err


def test_processed_live_idle_tick_and_ctrl_c_flush_new_lifetime(tmp_path, monkeypatch):
    events, flows = tmp_path / "events", tmp_path / "flows"
    monkeypatch.setattr(cli, "validate_interface", lambda interface: None)
    clock = [BASE]
    monkeypatch.setattr(cli, "utc_now", lambda: clock[0])

    def capture(**kwargs):
        kwargs["packet_handler"](make_dns_packet())
        clock[0] = BASE.replace(second=2)
        kwargs["tick_handler"]()  # no new packet needed to expire
        kwargs["packet_handler"](make_dns_packet(response=True, offset="4"))
        clock[0] = BASE.replace(second=4)
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "capture_live_periodic", capture)
    result = cli.run_processed_live("mock0", events, flows, ProcessingConfig(tracker=TrackerConfig(udp_idle_timeout=2)))
    saved, summaries = rows(events), rows(flows)
    assert result.stopped and result.packet_count == result.flow_count == 2
    assert [summary["end_reason"] for summary in summaries] == ["idle_timeout", "capture_stopped"]
    assert saved[0]["flow"]["flow_id"] != saved[1]["flow"]["flow_id"]
    assert all(event["packet"]["source"]["type"] == "interface" for event in saved)


def test_processed_live_capture_error_is_reported_and_existing_flow_is_finalized(tmp_path, monkeypatch):
    events, flows = tmp_path / "events", tmp_path / "flows"
    monkeypatch.setattr(cli, "validate_interface", lambda interface: None)
    monkeypatch.setattr(cli, "utc_now", lambda: BASE)

    def capture(**kwargs):
        kwargs["packet_handler"](make_dns_packet())
        raise PermissionError("capture failed")

    monkeypatch.setattr(cli, "capture_live_periodic", capture)
    with pytest.raises(PermissionError, match="capture failed"):
        cli.run_processed_live("mock0", events, flows)
    assert rows(flows)[0]["end_reason"] == "capture_error"


def test_live_invalid_interface_does_not_touch_outputs(tmp_path, monkeypatch):
    events, flows = tmp_path / "events", tmp_path / "flows"
    events.write_text("keep")
    monkeypatch.setattr("ids.capture.live.get_if_list", lambda: ["mock0"])
    with pytest.raises(ValueError, match="not found"):
        cli.run_processed_live("missing0", events, flows)
    assert events.read_text() == "keep" and not flows.exists()
