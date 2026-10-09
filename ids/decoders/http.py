"""One-pass HTTP URI/form/HTML decoding, preserving all raw parser fields."""

import base64
import binascii
import re
from dataclasses import asdict, dataclass, field
from email.message import Message
from typing import Any
from urllib.parse import unquote_to_bytes

from ids.config import DecoderConfig
from ids.decoders.html import decode_html
from ids.decoders.text import TextDecodeResult, decode_error, decode_text, limit_result
from ids.models import ApplicationInfo
from ids.processing_models import DecodeStatus, ProcessingError


INVALID_PERCENT = re.compile(rb"%(?![0-9a-fA-F]{2})")


@dataclass(slots=True)
class FormDecodeResult:
    parameters: dict[str, list[str]] | None
    charset: str | None
    status: DecodeStatus
    errors: list[ProcessingError] = field(default_factory=list)


@dataclass(slots=True)
class HttpDecodeResult:
    uri: TextDecodeResult | None = None
    form: FormDecodeResult | None = None
    html: TextDecodeResult | None = None
    status: DecodeStatus = DecodeStatus.SKIPPED
    errors: list[ProcessingError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _text_error(code: str, message: str) -> TextDecodeResult:
    return TextDecodeResult(None, None, DecodeStatus.ERROR, [decode_error(code, message)])


def _form_failure(result: TextDecodeResult) -> FormDecodeResult:
    return FormDecodeResult(None, result.charset, result.status, result.errors)


def _collect_errors(target: list[ProcessingError], errors: list[ProcessingError]) -> None:
    # Report the first occurrence of each code, avoiding unbounded repeated errors.
    known = {error.code for error in target}
    for error in errors:
        if error.code not in known:
            target.append(error)
            known.add(error.code)


def _decode_percent(
    raw: bytes, config: DecoderConfig, charset: str | None, context: str
) -> TextDecodeResult:
    result = decode_text(unquote_to_bytes(raw), config, charset=charset)
    invalid = INVALID_PERCENT.search(raw)
    if invalid:
        result.errors.append(decode_error(
            "invalid_percent_encoding",
            f"{context} has an invalid percent escape at byte {invalid.start()}",
        ))
        if result.status == DecodeStatus.OK:
            result.status = DecodeStatus.PARTIAL
    return result


def decode_uri(
    raw_uri: str | bytes,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> TextDecodeResult:
    """Percent-decode once; literal '+' stays '+' throughout the URI.

    Python string input is UTF-8. The event adapter passes bytes recovered from
    the parser's Latin-1 target. Invalid escapes stay literal and mark partial.
    Decoded separators are not reparsed or used to rewrite the raw URI.
    """
    config = config if config is not None else DecoderConfig()
    if not isinstance(raw_uri, (str, bytes)):
        return _text_error("invalid_http_uri", "HTTP URI must be text or bytes")
    if len(raw_uri) > config.max_input_bytes:
        return limit_result(config, "input_limit_exceeded", "HTTP URI exceeds input byte limit")
    try:
        raw = raw_uri.encode("utf-8") if isinstance(raw_uri, str) else raw_uri
    except UnicodeEncodeError:
        return _text_error("invalid_http_uri", "HTTP URI contains an invalid Unicode character")
    if len(raw) > config.max_input_bytes:
        return limit_result(config, "input_limit_exceeded", "HTTP URI exceeds input byte limit")

    return _decode_percent(raw, config, charset, "HTTP URI")


def decode_form(
    body: bytes,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> FormDecodeResult:
    """Split raw delimiters first, then decode '+' and percent escapes per field.

    Duplicate names retain ordered values. Blank values and empty names are
    retained; empty '&' fragments are ignored. Output limit counts decoded
    UTF-8 name/value bytes across all pairs, including repeated names.
    """
    config = config if config is not None else DecoderConfig()
    if not isinstance(body, bytes):
        return _form_failure(_text_error("invalid_form_input", "Form decoding requires bytes"))
    if len(body) > config.max_input_bytes:
        return _form_failure(limit_result(
            config, "input_limit_exceeded", "HTTP form body exceeds input byte limit"
        ))
    encoding = decode_text(b"", config, charset=charset)
    if encoding.status == DecodeStatus.ERROR:
        return _form_failure(encoding)
    parameters: dict[str, list[str]] = {}
    errors: list[ProcessingError] = []
    status = DecodeStatus.OK
    output_bytes = 0
    for pair in body.split(b"&"):
        if not pair:
            continue
        name, _, value = pair.partition(b"=")
        decoded = [
            _decode_percent(
                component.replace(b"+", b" "), config, encoding.charset, "HTTP form parameter"
            )
            for component in (name, value)
        ]
        for item in decoded:
            _collect_errors(errors, item.errors)
            if item.text is None:
                return FormDecodeResult(None, encoding.charset, item.status, errors)
            if item.status == DecodeStatus.PARTIAL:
                status = DecodeStatus.PARTIAL
            output_bytes += len(item.text.encode("utf-8"))
        if output_bytes > config.max_output_bytes:
            exceeded = limit_result(
                config, "output_limit_exceeded",
                "Decoded HTTP form name/value bytes exceed output limit", encoding.charset,
            )
            _collect_errors(errors, exceeded.errors)
            return FormDecodeResult(None, encoding.charset, exceeded.status, errors)
        parameters.setdefault(decoded[0].text, []).append(decoded[1].text)
    return FormDecodeResult(parameters, encoding.charset, status, errors)


def _raw_http_body(
    fields: dict[str, Any], config: DecoderConfig, context: str
) -> bytes | TextDecodeResult:
    raw = fields.get("body_base64")
    if raw is None:
        if fields.get("body_length") == 0:
            return b""
        return _text_error(
            f"missing_raw_{context}_body", f"HTTP {context} needs body_base64 or explicit body_length=0"
        )
    if not isinstance(raw, str):
        return _text_error(f"invalid_{context}_base64", "HTTP body Base64 must be text")
    if len(raw) > 4 * ((config.max_input_bytes + 2) // 3):
        return limit_result(
            config, "input_limit_exceeded", f"HTTP {context} Base64 exceeds input byte limit"
        )
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return _text_error(f"invalid_{context}_base64", "HTTP body has invalid Base64 data")


def decode_http(
    application: ApplicationInfo,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> HttpDecodeResult:
    """Decode URI/form and text/html or text/plain bodies without mutating raw fields."""
    config = config if config is not None else DecoderConfig()
    result = HttpDecodeResult()
    fields = application.fields
    if not isinstance(fields, dict):
        result.errors.append(decode_error("invalid_http_fields", "HTTP fields must be a dictionary"))
        result.status = DecodeStatus.ERROR
        return result
    if application.kind == "request":
        target = fields.get("target")
        if not isinstance(target, str):
            result.uri = _text_error("invalid_http_uri", "HTTP request is missing its raw target")
        elif len(target) > config.max_input_bytes:
            result.uri = limit_result(
                config, "input_limit_exceeded", "HTTP URI exceeds input byte limit"
            )
        else:
            try:
                raw_target = target.encode("latin-1")
            except UnicodeEncodeError:
                result.uri = _text_error("invalid_http_uri", "Parser target must preserve raw bytes as Latin-1")
            else:
                result.uri = decode_uri(raw_target, config, charset=charset)

    headers = fields.get("headers", {})
    if not isinstance(headers, dict):
        result.errors.append(decode_error("invalid_http_headers", "HTTP headers must be a dictionary"))
    else:
        content_type = next(
            (value for key, value in headers.items() if isinstance(key, str) and key.lower() == "content-type"),
            None,
        )
        if content_type is not None:
            if not isinstance(content_type, str):
                result.errors.append(decode_error("invalid_content_type", "HTTP Content-Type must be text"))
            else:
                mime = Message()
                mime["Content-Type"] = content_type
                if mime.get_content_type() == "application/x-www-form-urlencoded":
                    body = _raw_http_body(fields, config, "form")
                    result.form = _form_failure(body) if isinstance(body, TextDecodeResult) else decode_form(
                        body, config, charset=mime.get_param("charset", charset)
                    )
                elif mime.get_content_type() in ("text/html", "text/plain"):
                    encodings = [
                        value for key, value in headers.items()
                        if isinstance(key, str) and key.lower() in (
                            "content-encoding", "transfer-encoding"
                        )
                    ]
                    if any(not isinstance(value, str) for value in encodings):
                        result.html = _text_error(
                            "invalid_http_body_encoding", "HTTP body encoding headers must be text"
                        )
                    elif any(value.strip().lower() != "identity" for value in encodings):
                        result.html = TextDecodeResult(
                            None, None, DecodeStatus.SKIPPED,
                            [decode_error(
                                "unsupported_http_body_encoding",
                                "HTML decoding needs an uncompressed, unchunked HTTP body",
                            )],
                        )
                    else:
                        body = _raw_http_body(fields, config, "html")
                        result.html = body if isinstance(body, TextDecodeResult) else decode_html(
                            body, config, charset=mime.get_param("charset", charset)
                        )

    statuses = []
    for item in (result.uri, result.form, result.html):
        if item is not None:
            statuses.append(item.status)
            _collect_errors(result.errors, item.errors)
    if fields.get("message_complete") is False:
        result.errors.append(decode_error("incomplete_http_message", "HTTP parser reports an incomplete message"))
    if DecodeStatus.ERROR in statuses or any(
        error.code in ("invalid_http_headers", "invalid_content_type") for error in result.errors
    ):
        result.status = DecodeStatus.ERROR
    elif (result.errors and DecodeStatus.OK in statuses) or DecodeStatus.PARTIAL in statuses:
        result.status = DecodeStatus.PARTIAL
    elif DecodeStatus.OK in statuses:
        result.status = DecodeStatus.OK
    elif fields.get("message_complete") is False:
        result.status = DecodeStatus.PARTIAL
    return result
