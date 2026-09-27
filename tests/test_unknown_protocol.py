import base64
import json

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from ids.cli import run_pcap


def test_unknown_protocol_does_not_crash(tmp_path):
    pcap_path = tmp_path / "unknown-protocol.pcap"
    output_path = tmp_path / "unknown-protocol.jsonl"
    payloads = [
        b"CUSTOM/1.0 hello\r\n",
        b"\x01\x02\x03\x04unknown udp payload\xff",
        b"this is not an HTTP request\r\n",
    ]
    packets = [
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.11", dst="10.0.0.20")
            / TCP(sport=52000, dport=9999, flags="PA")
            / Raw(payloads[0])
        ),
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.12", dst="10.0.0.20")
            / UDP(sport=53000, dport=9999)
            / Raw(payloads[1])
        ),
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.13", dst="10.0.0.20")
            / TCP(sport=52001, dport=80, flags="PA")
            / Raw(payloads[2])
        ),
    ]

    wrpcap(str(pcap_path), packets)
    packet_count = run_pcap(pcap_path, output_path)
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert packet_count == 3
    assert len(events) == 3
    assert [event["packet_id"] for event in events] == [1, 2, 3]
    assert all(event["parse_status"] == "ok" for event in events)
    assert all(event["errors"] == [] for event in events)
    assert all(
        event["application"]
        == {"protocol": "UNKNOWN", "kind": None, "fields": {}}
        for event in events
    )

    assert [event["transport"]["protocol"] for event in events] == [
        "TCP",
        "UDP",
        "TCP",
    ]
    assert [event["transport"]["dst_port"] for event in events] == [
        9999,
        9999,
        80,
    ]

    for event, payload in zip(events, payloads, strict=True):
        assert event["payload"]["length"] == len(payload)
        assert base64.b64decode(event["payload"]["base64"]) == payload
