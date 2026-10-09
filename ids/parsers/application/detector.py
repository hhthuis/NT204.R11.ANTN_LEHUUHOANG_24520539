import re
import struct

from ids.parsers.application.mime import looks_like_mime


HTTP_REQUEST_LINE = re.compile(
    rb"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) "
    rb"\S+ HTTP/1\.[01](?:\r?\n|$)",
    re.IGNORECASE,
)
HTTP_RESPONSE_LINE = re.compile(
    rb"^HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?(?:\r?\n|$)",
    re.IGNORECASE,
)

SMTP_COMMAND_LINE = re.compile(
    rb"^(?:(?:HELO|EHLO|VRFY|EXPN|AUTH)\s+|"
    rb"(?:MAIL FROM:|RCPT TO:)\s*|"
    rb"(?:DATA|RSET|NOOP|QUIT|STARTTLS)(?:\s|\r?\n|$))",
    re.IGNORECASE,
)
SMTP_RESPONSE_LINE = re.compile(
    rb"^[2-5][0-9]{2}(?:[ -])[^\r\n]*(?:\r?\n|$)",
)

SMTP_PORTS = {25, 465, 587, 2525}
DNS_PORT = 53
SUPPORTED_DNS_OPCODES = {0, 1, 2, 4, 5}
MAX_DNS_RECORDS = 1000


def _looks_like_http(payload: bytes) -> bool:
    return bool(
        HTTP_REQUEST_LINE.match(payload)
        or HTTP_RESPONSE_LINE.match(payload)
    )


def _looks_like_smtp(
    payload: bytes,
    src_port: int,
    dst_port: int,
) -> bool:
    if SMTP_COMMAND_LINE.match(payload):
        return True

    uses_smtp_port = src_port in SMTP_PORTS or dst_port in SMTP_PORTS
    return uses_smtp_port and bool(SMTP_RESPONSE_LINE.match(payload) or looks_like_mime(payload))


def _skip_dns_name(message: bytes, offset: int) -> int | None:
    """Return the first byte after a DNS name, or None if it is invalid."""
    labels_seen = 0

    while offset < len(message):
        length = message[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                return None

            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer >= len(message):
                return None

            return offset + 2

        if length & 0xC0:
            return None

        offset += 1

        if length == 0:
            return offset

        if length > 63 or offset + length > len(message):
            return None

        offset += length
        labels_seen += 1

        if labels_seen > 127:
            return None

    return None


def _extract_dns_message(
    payload: bytes,
    transport_protocol: str,
) -> bytes | None:
    if transport_protocol == "UDP":
        return payload

    if transport_protocol != "TCP" or len(payload) < 2:
        return None

    declared_length = int.from_bytes(payload[:2], "big")

    if declared_length < 12 or declared_length > len(payload) - 2:
        return None

    return payload[2 : 2 + declared_length]


def _looks_like_dns(
    payload: bytes,
    transport_protocol: str,
    src_port: int,
    dst_port: int,
) -> bool:
    message = _extract_dns_message(payload, transport_protocol)

    if message is None or len(message) < 12:
        return False

    flags, question_count, answer_count, authority_count, additional_count = (
        struct.unpack("!HHHHH", message[2:12])
    )

    opcode = (flags >> 11) & 0x0F
    reserved_z_bit = flags & 0x0040
    total_records = (
        question_count
        + answer_count
        + authority_count
        + additional_count
    )

    if opcode not in SUPPORTED_DNS_OPCODES or reserved_z_bit:
        return False

    if total_records == 0 or total_records > MAX_DNS_RECORDS:
        return False

    if question_count > 0:
        offset = 12

        for _ in range(question_count):
            offset = _skip_dns_name(message, offset)
            if offset is None or offset + 4 > len(message):
                return False
            offset += 4

        return True

    is_response = bool(flags & 0x8000)
    uses_dns_port = src_port == DNS_PORT or dst_port == DNS_PORT
    return is_response and uses_dns_port


def detect_application_protocol(
    payload: bytes,
    transport_protocol: str,
    src_port: int,
    dst_port: int,
) -> str:
    """Detect HTTP, DNS or SMTP without depending only on port numbers."""
    if not payload:
        return "UNKNOWN"

    protocol = transport_protocol.upper()

    if protocol == "TCP":
        if _looks_like_http(payload):
            return "HTTP"

        if _looks_like_smtp(payload, src_port, dst_port):
            return "SMTP"

    if protocol in {"TCP", "UDP"} and _looks_like_dns(
        payload,
        protocol,
        src_port,
        dst_port,
    ):
        return "DNS"

    return "UNKNOWN"
