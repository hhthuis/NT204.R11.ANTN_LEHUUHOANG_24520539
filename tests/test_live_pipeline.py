import json
import sys

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP

from ids import cli


def test_argument_parser_accepts_pcap_source() -> None:
    parser = cli.build_argument_parser()

    args = parser.parse_args(["--pcap", "input.pcap"])

    assert args.pcap == "input.pcap"
    assert args.interface is None
    assert args.output == "output/events.jsonl"


def test_argument_parser_accepts_interface_source() -> None:
    parser = cli.build_argument_parser()

    args = parser.parse_args(
        [
            "--interface",
            "eth0",
            "--output",
            "output/live.jsonl",
        ]
    )

    assert args.pcap is None
    assert args.interface == "eth0"
    assert args.output == "output/live.jsonl"


def test_argument_parser_requires_exactly_one_source() -> None:
    parser = cli.build_argument_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([])

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--pcap",
                "input.pcap",
                "--interface",
                "eth0",
            ]
        )


def test_run_live_uses_shared_pipeline_and_writes_jsonl(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_path = tmp_path / "live-events.jsonl"
    http_payload = b"GET /live HTTP/1.1\r\nHost: example.test\r\n\r\n"
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=8080, flags="PA")
        / Raw(http_payload),
        Ether()
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=53000, dport=9999)
        / Raw(b"live udp"),
    ]

    for index, packet in enumerate(packets):
        packet.time = 1_800_000_000 + index

    def fake_capture_live(*, interface, packet_handler):
        assert interface == "eth0"

        for packet in packets:
            packet_handler(packet)

    monkeypatch.setattr(cli, "capture_live", fake_capture_live)

    packet_count = cli.run_live("eth0", output_path)
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert packet_count == 2
    assert len(events) == 2
    assert [event["packet_id"] for event in events] == [1, 2]
    assert all(
        event["source"] == {"type": "interface", "name": "eth0"}
        for event in events
    )
    assert events[0]["application"]["protocol"] == "HTTP"
    assert events[0]["application"]["fields"]["method"] == "GET"
    assert events[0]["application"]["fields"]["target"] == "/live"
    assert events[1]["transport"]["protocol"] == "UDP"
    assert events[1]["payload"]["preview"] == "live udp"


def test_main_dispatches_interface_to_run_live(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    received_arguments = {}

    def fake_run_live(*, interface, output_path):
        received_arguments["interface"] = interface
        received_arguments["output_path"] = output_path
        return 3

    monkeypatch.setattr(cli, "run_live", fake_run_live)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--interface",
            "eth0",
            "--output",
            "output/live.jsonl",
        ],
    )

    exit_code = cli.main()

    assert exit_code == 0
    assert received_arguments == {
        "interface": "eth0",
        "output_path": "output/live.jsonl",
    }
    assert (
        capsys.readouterr().out
        == "Processed 3 packets. Output: output/live.jsonl\n"
    )
