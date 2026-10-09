"""Replay existing lab PCAPs through the real CLI and verify both output files."""

import argparse
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from ids.capture.pcap import read_pcap
from ids.models import CaptureSource
from ids.pipeline import parse_packet


ROOT = Path(__file__).resolve().parents[2]
CASES = (
    "T01", "T02", "T03", "T04", "http-form", "T07", "T08",
    "T09/fin", "T09/rst", "T10", "T11", "T12", "T13",
)


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def verify_outputs(input_path, events, flows):
    # Check that wiring did not lose/reorder observations or modify the parser's
    # raw event. Protocol behavior itself has separate formal lab tests.
    raw = [json.loads(json.dumps(parse_packet(packet, index, CaptureSource("pcap", input_path.name)).to_dict()))
           for index, packet in enumerate(read_pcap(input_path), 1)]
    assert [event["packet"] for event in events] == raw, "Missing, reordered or changed raw packets"
    grouped = defaultdict(list)
    for event in events:
        if event["processing_action"] == "skip_tracking":
            assert event["flow"] is None
            assert event["reason"], "Skipped observation must explain why"
        else:
            assert event["processing_action"] == "track" and event["flow"] is not None
            grouped[event["flow"]["flow_id"]].append(event)
    identifiers = [flow["flow_id"] for flow in flows]
    assert len(identifiers) == len(set(identifiers)), "Duplicate final flow summaries"
    assert set(identifiers) == set(grouped), "Missing or unassociated final flow summary"
    for flow in flows:
        observations = grouped[flow["flow_id"]]
        assert flow["schema_version"] == "1.0"
        assert flow["end_reason"] in {"capture_eof", "idle_timeout", "capacity_eviction", "tcp_reuse"}
        assert flow["packet_count"] == len(observations)
        assert flow["byte_count"] == sum(event["packet"]["captured_length"] for event in observations)
        for direction in ("forward", "backward"):
            selected = [event for event in observations if event["flow"]["direction"] == direction]
            assert flow[f"{direction}_packet_count"] == len(selected)
            assert flow[f"{direction}_byte_count"] == sum(event["packet"]["captured_length"] for event in selected)
            sender = flow["endpoint_a" if direction == "forward" else "endpoint_b"]
            receiver = flow["endpoint_b" if direction == "forward" else "endpoint_a"]
            for event in selected:
                network, transport = event["packet"]["network"], event["packet"]["transport"]
                assert {"ip": network["src_ip"], "port": transport["src_port"]} == sender
                assert {"ip": network["dst_ip"], "port": transport["dst_port"]} == receiver
                assert transport["protocol"] == flow["protocol"]
        times = [datetime.fromisoformat(event["packet"]["timestamp"]) for event in observations]
        assert datetime.fromisoformat(flow["start_time"]) == min(times)
        assert datetime.fromisoformat(flow["last_seen"]) == max(times)
        assert flow["duration"] == (max(times) - min(times)).total_seconds()
        assert datetime.fromisoformat(flow["end_time"]) >= max(times)
        for flag in ("SYN", "ACK", "FIN", "RST"):
            expected = sum(flag in event["packet"]["transport"]["fields"].get("flags", []) for event in observations)
            assert flow[f"{flag.lower()}_count"] == expected, "Invented or missing wire flags"


def verify_case(label, events, flows):
    # Literal expectations verify behavior through the executable, in addition
    # to the joins/counts above; these do not come from the output being tested.
    if label == "T01":
        assert events[0]["decoded"]["http"]["uri"]["text"] == "/search?q=' OR 1=1"
        assert events[1]["decoded"]["http"]["uri"]["text"] == "/a+b?q=x+y+z"
    elif label == "http-form":
        parameters = events[0]["decoded"]["http"]["form"]["parameters"]
        assert parameters["tag"] == ["one", "two"] and parameters["name"] == ["Alice Bob"]
        assert parameters["plus"] == ["+"]
    elif label == "T07":
        assert [event["flow"]["state"] for event in events] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]
        assert len(flows) == 1 and flows[0]["state"] == "ESTABLISHED"
    elif label in {"T09/fin", "T09/rst"}:
        assert len(flows) == 1
        assert flows[0]["state"] == ("CLOSED" if label.endswith("fin") else "RESET")
    elif label == "T10":
        assert len(events) == 2 and len(flows) == 1
        assert flows[0]["protocol"] == "UDP" and flows[0]["application_protocol"] == "DNS"
        assert flows[0]["byte_count"] == 172 and flows[0]["state"] is None
        assert [event["flow"]["direction"] for event in events] == ["forward", "backward"]
    elif label == "T12":
        assert len(events) == 4 and len(flows) == 3
        assert sum(flow["byte_count"] for flow in flows) == 192
        assert [flow["end_reason"] for flow in flows] == ["idle_timeout", "idle_timeout", "capture_eof"]
        assert events[1]["flow"]["flow_id"] != events[3]["flow"]["flow_id"]
        assert all(flow["end_time"] == "2026-10-09T00:00:04.100000Z" for flow in flows)


def reproduce(directory):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    report = []
    for label in CASES:
        source_dir = ROOT / "TEST/lab02" / label
        input_path = source_dir / "input.pcap"
        config_source = source_dir / "config.toml"
        if not config_source.exists():
            config_source = ROOT / "config/default.toml"
        output_dir = directory / "cli" / label
        output_dir.mkdir(parents=True, exist_ok=True)
        config_path = output_dir / "config.toml"
        config_path.write_bytes(config_source.read_bytes())
        events_path, flows_path = output_dir / "events.jsonl", output_dir / "flows.jsonl"
        arguments = ["main.py", "--mode", "processed", "--pcap", str(input_path.relative_to(ROOT)),
                     "--config", str(config_path), "--output", str(events_path), "--flows-output", str(flows_path)]
        result = subprocess.run([sys.executable, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"{label}: exit={result.returncode}\n{result.stderr}"
        events, flows = read_rows(events_path), read_rows(flows_path)
        verify_outputs(input_path, events, flows)
        verify_case(label, events, flows)
        assert f"Processed {len(events)} packets, wrote {len(flows)} flow summaries." in result.stdout
        # Report paths relative to the repo/output dir for reproducible evidence.
        entry = {
            "case": label, "input": str(input_path.relative_to(ROOT)),
            "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "config_source": str(config_source.relative_to(ROOT)),
            "config": str(config_path.relative_to(directory)),
            "events": str(events_path.relative_to(directory)), "flows": str(flows_path.relative_to(directory)),
            "packet_count": len(events), "tracked_packet_count": sum(event["flow"] is not None for event in events),
            "flow_count": len(flows), "exit_code": result.returncode,
            "stdout": result.stdout.replace(str(directory), "<output-dir>"), "stderr": result.stderr,
            "status": "PASS",
        }
        report.append(entry)
        print(f"{label}: PASS; packets={entry['packet_count']}; tracked={entry['tracked_packet_count']}; flows={entry['flow_count']}")
    (directory / "cases.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Task 17 CLI replay PASS: {len(report)} subprocess runs; each raw event preserved; all tracked observations summarized once")
    return report


def main():
    parser = argparse.ArgumentParser(description="Reproduce Task 17 through CLI subprocesses")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "TEST/lab02/task17")
    reproduce(parser.parse_args().output_dir)


if __name__ == "__main__":
    main()
