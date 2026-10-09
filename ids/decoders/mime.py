"""Bounded, header-directed MIME Base64/Quoted-Printable body decoding."""

import base64
import binascii
import quopri
import re
from dataclasses import asdict, dataclass, field
from email.message import Message
from typing import Any

from ids.config import DecoderConfig
from ids.decoders.text import TextDecodeResult, decode_error, decode_text, limit_result
from ids.models import ApplicationInfo
from ids.processing_models import DecodeStatus, ProcessingError


BASE64_WHITESPACE = re.compile(rb"[ \t\r\n]+")
QP_ESCAPE = re.compile(rb"=([0-9A-Fa-f]{2})|=(\r?\n)")
INVALID_QP_ESCAPE = re.compile(rb"=(?![0-9A-Fa-f]{2}|\r?\n)")
TRAILING_SPACE = re.compile(rb"[ \t]+(?=\r?$)", re.MULTILINE)
DOT_STUFFING = re.compile(rb"(?m)^\.(?=[^\r\n])")


@dataclass(slots=True)
class MimeDecodeResult:
    transfer_encoding: str | None = None
    content_type: str | None = None
    charset: str | None = None
    text: str | None = None
    body_base64: str | None = None
    body_length: int | None = None
    status: DecodeStatus = DecodeStatus.SKIPPED
    errors: list[ProcessingError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _failure(result: TextDecodeResult) -> MimeDecodeResult:
    return MimeDecodeResult(charset=result.charset, status=result.status, errors=result.errors)


def _error(code: str, message: str) -> MimeDecodeResult:
    return MimeDecodeResult(status=DecodeStatus.ERROR, errors=[decode_error(code, message)])


def decode_mime_body(
    body: bytes,
    transfer_encoding: str | None,
    config: DecoderConfig | None = None,
    *,
    content_type: str = "text/plain",
    charset: str | None = None,
) -> MimeDecodeResult:
    """Decode once by declared encoding; never guess from Base64-looking text.

    MIME Base64 permits line wrapping/space/tab; malformed/noncanonical data
    returns error. Bad QP escapes stay literal and mark partial. '_' is literal
    (body decoding, not RFC 2047 header decoding). Text supports ASCII/UTF-8;
    binary retains decoded bytes in Base64 without character decoding.
    """
    config = config if config is not None else DecoderConfig()
    if not isinstance(body, bytes):
        return _error("invalid_mime_body", "MIME body decoding requires bytes")
    if len(body) > config.max_input_bytes:
        return _failure(limit_result(config, "input_limit_exceeded", "MIME body exceeds input byte limit"))
    if transfer_encoding is not None and not isinstance(transfer_encoding, str):
        return _error("invalid_transfer_encoding", "MIME Content-Transfer-Encoding must be text")
    if not isinstance(content_type, str):
        return _error("invalid_mime_content_type", "MIME Content-Type must be text")
    encoding = transfer_encoding.strip().lower() if transfer_encoding is not None else "7bit"
    media_type = content_type.strip().lower()
    result = MimeDecodeResult(transfer_encoding=encoding, content_type=media_type)
    if media_type.startswith(("multipart/", "message/")):
        result.errors.append(decode_error("unsupported_mime_structure", "Nested/multipart MIME entities are not implemented"))
        return result
    if encoding == "base64":
        compact = BASE64_WHITESPACE.sub(b"", body)
        try:
            decoded = base64.b64decode(compact, validate=True)
            if base64.b64encode(decoded) != compact:
                raise ValueError("noncanonical Base64 padding")
        except (binascii.Error, ValueError):
            result.status = DecodeStatus.ERROR
            result.errors.append(decode_error("invalid_mime_base64", "MIME body contains invalid Base64 data or padding"))
            return result
    elif encoding == "quoted-printable":
        encoded = TRAILING_SPACE.sub(b"", body)
        invalid = INVALID_QP_ESCAPE.search(encoded)
        if invalid:
            result.errors.append(decode_error(
                "invalid_quoted_printable",
                f"MIME body has an invalid Quoted-Printable escape at byte {invalid.start()}",
            ))
            decoded = QP_ESCAPE.sub(
                lambda match: bytes.fromhex(match[1].decode("ascii")) if match[1] else b"",
                encoded,
            )
        else:
            decoded = quopri.decodestring(encoded, header=False)
    elif encoding in ("7bit", "8bit", "binary"):
        decoded = body
    else:
        result.errors.append(decode_error("unsupported_transfer_encoding", f"Unsupported MIME transfer encoding: {encoding!r}"))
        return result

    if len(decoded) > config.max_output_bytes:
        failure = limit_result(config, "output_limit_exceeded", "MIME decoded bytes exceed output byte limit")
        result.status = failure.status
        result.errors.extend(failure.errors)
        return result
    result.body_base64 = base64.b64encode(decoded).decode("ascii")
    result.body_length = len(decoded)
    result.status = DecodeStatus.PARTIAL if result.errors else DecodeStatus.OK
    if media_type.startswith("text/"):
        text = decode_text(decoded, config, charset=charset)
        result.charset, result.text = text.charset, text.text
        result.errors.extend(text.errors)
        if text.status != DecodeStatus.OK:
            result.status = text.status
        if text.status in (DecodeStatus.SKIPPED, DecodeStatus.ERROR) and any(
            error.code.endswith("limit_exceeded") for error in text.errors
        ):
            result.body_base64 = None
            result.body_length = None
    return result


def _single_header(headers: dict, name: str) -> str | None | MimeDecodeResult:
    values = []
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            values.extend(value if isinstance(value, list) else [value])
    if not values:
        return None
    if len(values) != 1:
        return _error("ambiguous_mime_header", f"MIME {name} must not occur more than once")
    if not isinstance(values[0], str):
        return _error("invalid_mime_header", f"MIME {name} must be text")
    return values[0]


def decode_mime(
    application: ApplicationInfo,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> MimeDecodeResult:
    """Decode a parsed single MIME entity; raw parser fields remain untouched."""
    config = config if config is not None else DecoderConfig()
    fields = application.fields
    if not isinstance(fields, dict) or not isinstance(fields.get("headers"), dict):
        return _error("invalid_mime_fields", "MIME fields need a headers dictionary")
    headers = fields["headers"]
    values = [_single_header(headers, name) for name in ("content-transfer-encoding", "content-type")]
    for value in values:
        if isinstance(value, MimeDecodeResult):
            return value
    present = [value for value in values if value is not None]
    if sum(len(value) for value in present) > config.max_input_bytes or sum(
        len(value.encode("utf-8", errors="replace")) for value in present
    ) > config.max_input_bytes:
        return _failure(limit_result(config, "input_limit_exceeded", "MIME decoding headers exceed input byte limit"))
    encoding, content_type = values
    mime = Message()
    if content_type is not None:
        mime["Content-Type"] = content_type
    media_type = mime.get_content_type()
    # Without a declared MIME charset, caller/config supplies the fallback.
    requested_charset = mime.get_param("charset", charset)
    raw = fields.get("body_base64")
    if raw is None:
        if fields.get("body_length") == 0:
            body = b""
        else:
            return _error("missing_raw_mime_body", "MIME needs body_base64 or explicit body_length=0")
    elif not isinstance(raw, str):
        return _error("invalid_mime_body_base64", "Stored MIME body Base64 must be text")
    elif len(raw) > 4 * ((config.max_input_bytes + 2) // 3):
        return _failure(limit_result(config, "input_limit_exceeded", "Stored MIME body Base64 exceeds input byte limit"))
    else:
        try:
            body = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            return _error("invalid_mime_body_base64", "Stored MIME body has invalid Base64 data")
    if len(body) > config.max_input_bytes:
        return _failure(limit_result(config, "input_limit_exceeded", "Raw MIME wire body exceeds input byte limit"))
    if fields.get("smtp_data") is True:
        body = DOT_STUFFING.sub(b"", body)
    result = decode_mime_body(body, encoding, config, content_type=media_type, charset=requested_charset)
    if fields.get("message_complete") is False:
        result.errors.append(decode_error("incomplete_mime_message", "MIME parser reports an incomplete or malformed message"))
        if result.status == DecodeStatus.OK:
            result.status = DecodeStatus.PARTIAL
    return result
