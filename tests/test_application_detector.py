from scapy.layers.dns import DNS, DNSQR, DNSRR

from ids.parsers.application.detector import detect_application_protocol


def detect(
    payload: bytes,
    transport: str = "TCP",
    src_port: int = 50000,
    dst_port: int = 9999,
) -> str:
    return detect_application_protocol(
        payload=payload,
        transport_protocol=transport,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_detects_http_request_on_non_standard_port():
    payload = b"GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n"

    assert detect(payload, dst_port=54321) == "HTTP"


def test_detects_http_response():
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    assert detect(payload, src_port=8080) == "HTTP"


def test_detects_dns_query_on_non_standard_udp_port():
    payload = bytes(DNS(id=100, qd=DNSQR(qname="example.test")))

    assert detect(
        payload,
        transport="UDP",
        src_port=53000,
        dst_port=53001,
    ) == "DNS"


def test_detects_dns_response():
    payload = bytes(
        DNS(
            id=100,
            qr=1,
            qd=DNSQR(qname="example.test"),
            an=DNSRR(rrname="example.test", rdata="192.0.2.10"),
        )
    )

    assert detect(
        payload,
        transport="UDP",
        src_port=53,
        dst_port=53000,
    ) == "DNS"


def test_detects_length_prefixed_dns_over_tcp():
    dns_message = bytes(DNS(id=101, qd=DNSQR(qname="example.test")))
    payload = len(dns_message).to_bytes(2, "big") + dns_message

    assert detect(
        payload,
        transport="TCP",
        src_port=53000,
        dst_port=53,
    ) == "DNS"


def test_detects_smtp_command_on_non_standard_port():
    assert detect(b"EHLO mail.example.test\r\n", dst_port=2600) == "SMTP"
    assert detect(b"MAIL FROM:<alice@example.test>\r\n", dst_port=2600) == "SMTP"


def test_detects_smtp_response_on_smtp_port():
    payload = b"250-mail.example.test\r\n250 STARTTLS\r\n"

    assert detect(payload, src_port=25, dst_port=51000) == "SMTP"


def test_detects_smtp_354_response_on_smtp_port():
    payload = b"354 End data with <CR><LF>.<CR><LF>\r\n"

    assert detect(payload, src_port=25, dst_port=51000) == "SMTP"


def test_port_alone_does_not_force_a_protocol():
    assert detect(b"not an HTTP message", dst_port=80) == "UNKNOWN"
    assert detect(b"not a DNS message", transport="UDP", dst_port=53) == "UNKNOWN"
    assert detect(b"not an SMTP message", dst_port=25) == "UNKNOWN"


def test_truncated_dns_message_is_unknown():
    payload = (
        b"\x12\x34"  # Transaction ID
        b"\x01\x00"  # Standard query flags
        b"\x00\x01"  # One question
        b"\x00\x00\x00\x00\x00\x00"
        b"\x07example"  # Truncated name without terminator/type/class
    )

    assert detect(
        payload,
        transport="UDP",
        src_port=53000,
        dst_port=53,
    ) == "UNKNOWN"


def test_empty_payload_is_unknown():
    assert detect(b"", dst_port=80) == "UNKNOWN"
