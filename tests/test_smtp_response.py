import json

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.cli import run_pcap


def test_smtp_responses(tmp_path):
    pcap_path = tmp_path / "smtp-response.pcap"
    output_path = tmp_path / "smtp-response.jsonl"
    payloads = [
        b"220 mail.example.test ESMTP ready\r\n",
        (
            b"250-mail.example.test\r\n"
            b"250-PIPELINING\r\n"
            b"250 STARTTLS\r\n"
        ),
        b"354 End data with <CR><LF>.<CR><LF>\r\n",
        b"550 5.1.1 Mailbox unavailable\r\n",
    ]

    packets = [
        (
            Ether(
                src="02:00:00:00:00:02",
                dst="02:00:00:00:00:01",
            )
            / IP(src="10.0.0.25", dst="10.0.0.10")
            / TCP(sport=25, dport=51000, flags="PA")
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
        event["application"]["kind"] == "response"
        for event in events
    )
    assert all(
        event["application"]["fields"]["message_complete"] is True
        for event in events
    )

    fields = [event["application"]["fields"] for event in events]
    assert [response["status_code"] for response in fields] == [
        220,
        250,
        354,
        550,
    ]

    assert fields[0]["message"] == "mail.example.test ESMTP ready"
    assert fields[0]["multiline"] is False

    assert fields[1]["multiline"] is True
    assert fields[1]["messages"] == [
        "mail.example.test",
        "PIPELINING",
        "STARTTLS",
    ]
    assert fields[1]["responses"][0]["complete"] is True

    assert fields[2]["message"] == "End data with <CR><LF>.<CR><LF>"
    assert fields[2]["multiline"] is False

    assert fields[3]["message"] == "5.1.1 Mailbox unavailable"
    assert fields[3]["multiline"] is False
    assert all(response["response_count"] == 1 for response in fields)
