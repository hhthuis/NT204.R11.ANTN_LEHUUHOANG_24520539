import json

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.cli import run_pcap


def test_smtp_commands(tmp_path):
    pcap_path = tmp_path / "smtp-command.pcap"
    output_path = tmp_path / "smtp-command.jsonl"
    payloads = [
        b"HELO legacy.example.test\r\n",
        b"EHLO client.example.test\r\n",
        b"MAIL FROM:<alice@example.test> SIZE=123\r\n",
        b"RCPT TO:<bob@example.test>\r\n",
    ]

    packets = [
        (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="10.0.0.10", dst="10.0.0.25")
            / TCP(sport=51000, dport=2526, flags="PA")
            / Raw(payload)
        )
        for payload in payloads
    ]

    wrpcap(str(pcap_path), packets)
    packet_count = run_pcap(pcap_path, output_path)
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert packet_count == 4
    assert len(events) == 4
    assert all(event["parse_status"] == "ok" for event in events)
    assert all(event["errors"] == [] for event in events)
    assert all(
        event["application"]["protocol"] == "SMTP"
        for event in events
    )
    assert all(
        event["application"]["kind"] == "command"
        for event in events
    )
    assert all(
        event["application"]["fields"]["message_complete"] is True
        for event in events
    )

    helo_fields = events[0]["application"]["fields"]
    assert helo_fields["command"] == "HELO"
    assert helo_fields["domain"] == "legacy.example.test"

    ehlo_fields = events[1]["application"]["fields"]
    assert ehlo_fields["command"] == "EHLO"
    assert ehlo_fields["domain"] == "client.example.test"

    mail_fields = events[2]["application"]["fields"]
    assert mail_fields["command"] == "MAIL FROM"
    assert mail_fields["mailbox"] == "alice@example.test"
    assert mail_fields["parameters"] == ["SIZE=123"]

    rcpt_fields = events[3]["application"]["fields"]
    assert rcpt_fields["command"] == "RCPT TO"
    assert rcpt_fields["mailbox"] == "bob@example.test"
