"""One-pass HTML5 entity decoding of bounded ASCII/UTF-8 text bytes."""

import re
from dataclasses import replace
from html import unescape

from ids.config import DecoderConfig
from ids.decoders.text import TextDecodeResult, decode_error, decode_text, limit_result
from ids.processing_models import DecodeStatus


NUMERIC_ENTITY = re.compile(r"&#(?:[xX]([0-9a-fA-F]+)|([0-9]+));?")


def decode_html(
    payload: bytes,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> TextDecodeResult:
    """Decode entities once, retaining unknown names using HTML5 rules.

    Character decoding happens first. max_output_bytes applies to the final
    text, not the longer entity spelling. Temporary character text is bounded
    by at most three UTF-8 bytes per input byte (invalid-byte replacement).
    Invalid numeric scalars become U+FFFD and mark partial. No HTML is executed.
    """
    config = config if config is not None else DecoderConfig()
    character_config = replace(
        config, max_output_bytes=max(config.max_output_bytes, 3 * config.max_input_bytes)
    )
    result = decode_text(payload, character_config, charset=charset)
    if result.text is None:
        return result

    invalid_offset: int | None = None

    def numeric_reference(match: re.Match[str]) -> str:
        nonlocal invalid_offset
        hexadecimal, decimal = match.groups()
        digits = (hexadecimal if hexadecimal is not None else decimal).lstrip("0") or "0"
        base = 16 if hexadecimal is not None else 10
        # Avoid converting attacker-controlled thousands of digits to an int.
        value = int(digits, base) if len(digits) <= (6 if base == 16 else 7) else 0x110000
        if value == 0 or value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
            if invalid_offset is None:
                invalid_offset = match.start()
            return "\ufffd"
        # Canonical spelling also avoids Python's int limit on leading zeros.
        return f"&#{value};"

    text = unescape(NUMERIC_ENTITY.sub(numeric_reference, result.text))
    if invalid_offset is not None:
        result.errors.append(decode_error(
            "invalid_html_entity",
            f"HTML numeric entity has an invalid Unicode scalar at character {invalid_offset}",
        ))
        result.status = DecodeStatus.PARTIAL

    output_size = len(text.encode("utf-8"))
    if output_size > config.max_output_bytes:
        exceeded = limit_result(
            config, "output_limit_exceeded",
            f"HTML decoded output length {output_size} exceeds {config.max_output_bytes} UTF-8 bytes",
            result.charset,
        )
        exceeded.errors = result.errors + exceeded.errors
        return exceeded
    result.text = text
    return result
