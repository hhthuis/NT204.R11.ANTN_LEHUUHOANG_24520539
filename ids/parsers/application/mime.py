"""Extract MIME headers and raw body without decoding transfer encodings."""

import base64
import re
from dataclasses import dataclass, field

from ids.models import ApplicationInfo


MIME_FIRST_HEADER = re.compile(
    rb"^(?:From|To|Cc|Bcc|Subject|Date|Message-ID|Received|Return-Path|Sender|"
    rb"Reply-To|Delivered-To|MIME-Version|Content-Type|"
    rb"Content-Transfer-Encoding):", re.IGNORECASE | re.MULTILINE,
)
HEADER_NAME = re.compile(rb"^[\x21-\x39\x3b-\x7e]+$")
DATA_PREFIX = re.compile(rb"^DATA\r?\n", re.IGNORECASE)
SMTP_TERMINATOR = re.compile(rb"(?m)^\.\r?\n")


@dataclass(slots=True)
class MimeParseResult:
    application: ApplicationInfo
    complete: bool
    warnings: list[str] = field(default_factory=list)


def looks_like_mime(payload: bytes) -> bool:
    message = DATA_PREFIX.sub(b"", payload, count=1)
    name, colon, _ = message.split(b"\n", 1)[0].partition(b":")
    if not colon or not HEADER_NAME.fullmatch(name):
        return False
    head = re.split(rb"\r?\n\r?\n", message, maxsplit=1)[0]
    return bool(MIME_FIRST_HEADER.search(head))


def parse_mime(payload: bytes, *, smtp_data: bool = False) -> MimeParseResult:
    """Extract a single entity; SMTP framing is removed only in smtp_data mode.

    body_base64 retains wire body bytes including dot stuffing. A decoder may
    undo stuffing in a separate representation. Raw payload retains DATA and
    the terminator. No TCP stream state is inferred from packet boundaries.
    """
    message = DATA_PREFIX.sub(b"", payload, count=1) if smtp_data else payload
    remaining_bytes = 0
    terminated = False
    if smtp_data:
        terminator = SMTP_TERMINATOR.search(message)
        if terminator:
            remaining_bytes = len(message) - terminator.end()
            message = message[:terminator.start()]
            terminated = True

    separator = re.search(rb"\r?\n\r?\n", message)
    head = message[:separator.start()] if separator else message
    body = message[separator.end():] if separator else None
    warnings = []
    if separator is None:
        warnings.append("MIME headers are missing their blank-line separator")
    if smtp_data and not terminated:
        warnings.append("SMTP DATA has no captured end-of-data terminator")
    if remaining_bytes:
        warnings.append("Bytes after SMTP DATA terminator are not parsed as another message")

    headers: dict[str, list[str]] = {}
    previous: str | None = None
    for line in head.splitlines():
        if line.startswith((b" ", b"\t")):
            if previous is None:
                warnings.append("MIME header continuation has no preceding header")
            else:
                headers[previous][-1] += " " + line.strip().decode("latin-1")
            continue
        name, colon, value = line.partition(b":")
        if not colon or not HEADER_NAME.fullmatch(name):
            warnings.append("MIME header line has an invalid name or no colon")
            previous = None
            continue
        previous = name.decode("ascii").lower()
        headers.setdefault(previous, []).append(value.strip().decode("latin-1"))

    complete = not warnings
    application = ApplicationInfo(
        protocol="SMTP" if smtp_data else "MIME", kind="message",
        fields={
            "headers": headers,
            "headers_base64": base64.b64encode(head).decode("ascii"),
            "body_base64": base64.b64encode(body).decode("ascii") if body else None,
            "body_length": len(body) if body is not None else None,
            "smtp_data": smtp_data, "smtp_terminated": terminated,
            "message_complete": complete, "remaining_bytes": remaining_bytes,
        },
    )
    return MimeParseResult(application, complete, warnings)
