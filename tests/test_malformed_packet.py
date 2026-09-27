import json

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.cli import run_pcap


def test_malformed_packets_do_not_crash_pipeline(tmp_path):
    pcap_path = tmp_path / "malformed-packet.pcap"
    output_path = tmp_path / "malformed-packet.jsonl"
    packets = [
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
                type=0x0800,
            )
            / Raw(b"\x45\x00\x00\x14\x00\x01\x00\x00")
        ),
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.11", dst="10.0.0.20", proto=6)
            / Raw(b"\x00\x50\x13\x88")
        ),
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.12", dst="10.0.0.20")
            / TCP(sport=52000, dport=80, flags="PA")
            / Raw(b"GET / HTTP/1.1\r\nMalformed header\r\n\r\n")
        ),
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.13", dst="10.0.0.25")
            / TCP(sport=52001, dport=25, flags="PA")
            / Raw(b"EHLO client.example.test")
        ),
    ]

    wrpcap(str(pcap_path), packets)
    packet_count = run_pcap(pcap_path, output_path)
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert packet_count == 4
    assert len(events) == 4
    assert [event["packet_id"] for event in events] == [1, 2, 3, 4]

    truncated_ipv4 = events[0]
    assert truncated_ipv4["parse_status"] == "malformed"
    assert truncated_ipv4["network"] is None
    assert truncated_ipv4["transport"] is None
    assert truncated_ipv4["errors"][0]["stage"] == "network"
    assert "IPv4" in truncated_ipv4["errors"][0]["message"]
    assert "truncated" in truncated_ipv4["errors"][0]["message"]

    missing_tcp = events[1]
    assert missing_tcp["parse_status"] == "malformed"
    assert missing_tcp["network"]["protocol"] == "IPv4"
    assert missing_tcp["transport"] is None
    assert missing_tcp["errors"][0]["stage"] == "transport"
    assert "TCP" in missing_tcp["errors"][0]["message"]
    assert "truncated" in missing_tcp["errors"][0]["message"]

    malformed_http = events[2]
    assert malformed_http["parse_status"] == "partial"
    assert malformed_http["transport"]["protocol"] == "TCP"
    assert malformed_http["application"]["protocol"] == "HTTP"
    assert malformed_http["errors"][0]["stage"] == "http"
    assert "without colon" in malformed_http["errors"][0]["message"]

    incomplete_smtp = events[3]
    assert incomplete_smtp["parse_status"] == "partial"
    assert incomplete_smtp["application"]["protocol"] == "SMTP"
    assert incomplete_smtp["application"]["kind"] == "command"
    assert incomplete_smtp["application"]["fields"]["command"] == "EHLO"
    assert incomplete_smtp["application"]["fields"]["message_complete"] is False
    assert incomplete_smtp["errors"] == [
        {
            "stage": "smtp",
            "message": "SMTP line is missing its line terminator",
        }
    ]
