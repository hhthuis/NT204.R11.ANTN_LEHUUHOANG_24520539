"""Bounded ASCII/UTF-8 character decoding with explicit failure results."""

import codecs
from dataclasses import dataclass, field

from ids.config import DecoderConfig, DecodeLimitPolicy, InvalidBytesPolicy
from ids.processing_models import DecodeStatus, ProcessingError, ProcessingStage


@dataclass(slots=True)
class TextDecodeResult:
    text: str | None
    charset: str | None
    status: DecodeStatus
    errors: list[ProcessingError] = field(default_factory=list)


def decode_error(code: str, message: str) -> ProcessingError:
    return ProcessingError(ProcessingStage.DECODE, code, message)


def limit_result(
    config: DecoderConfig,
    code: str,
    message: str,
    charset: str | None = None,
) -> TextDecodeResult:
    status = (
        DecodeStatus.SKIPPED
        if config.limit_policy == DecodeLimitPolicy.SKIP
        else DecodeStatus.ERROR
    )
    return TextDecodeResult(None, charset, status, [decode_error(code, message)])


def decode_text(
    payload: bytes,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> TextDecodeResult:
    """Decode byte data without raising for invalid bytes or unsupported charset.

    max_output_bytes measures the UTF-8 representation of returned text, before
    JSON escaping. Replacement may expand one bad byte to three output bytes.
    Input is bounded before decoding; oversized output is discarded, not cut.
    The first invalid sequence is reported even under the replacement policy.
    """
    config = config if config is not None else DecoderConfig()
    requested = config.default_charset if charset is None else charset
    try:
        if not isinstance(requested, str):
            raise ValueError("charset is not a string")
        encoding = codecs.lookup(requested).name
        if encoding not in ("ascii", "utf-8"):
            raise ValueError("charset is not supported")
    except (LookupError, ValueError):
        return TextDecodeResult(
            None, None, DecodeStatus.ERROR,
            [decode_error("unsupported_charset", "Character decoder supports only ASCII and UTF-8")],
        )

    if not isinstance(payload, bytes):
        return TextDecodeResult(
            None, encoding, DecodeStatus.ERROR,
            [decode_error("invalid_text_input", "Character decoding requires bytes")],
        )
    if len(payload) > config.max_input_bytes:
        return limit_result(
            config, "input_limit_exceeded",
            f"Input length {len(payload)} exceeds {config.max_input_bytes} bytes",
            encoding,
        )

    errors: list[ProcessingError] = []
    status = DecodeStatus.OK
    try:
        text = payload.decode(encoding, errors="strict")
    except UnicodeDecodeError as error:
        errors.append(decode_error(
            "invalid_character_sequence",
            f"Invalid {encoding} sequence at bytes {error.start}:{error.end}: {error.reason}",
        ))
        if config.invalid_bytes_policy == InvalidBytesPolicy.STRICT:
            return TextDecodeResult(None, encoding, DecodeStatus.ERROR, errors)
        text = payload.decode(encoding, errors="replace")
        status = DecodeStatus.PARTIAL

    output_size = len(text.encode("utf-8"))
    if output_size > config.max_output_bytes:
        result = limit_result(
            config, "output_limit_exceeded",
            f"Output length {output_size} exceeds {config.max_output_bytes} UTF-8 bytes",
            encoding,
        )
        result.errors = errors + result.errors
        return result
    return TextDecodeResult(text, encoding, status, errors)
