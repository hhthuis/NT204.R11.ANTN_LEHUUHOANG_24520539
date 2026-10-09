"""Event decoder: HTTP fields or character decoding of a raw payload.

MIME and HTML decoding are added in later tasks. This function is not yet
wired into the PCAP/live CLI pipeline.
"""

import base64
import binascii

from ids.config import DecoderConfig
from ids.decoders.http import decode_http
from ids.decoders.text import TextDecodeResult, decode_error, decode_text, limit_result
from ids.models import PacketEvent
from ids.processing_models import DecodeStatus, ProcessedEvent


def decode_event(
    event: PacketEvent,
    config: DecoderConfig | None = None,
    *,
    charset: str | None = None,
) -> ProcessedEvent:
    """Decode from Base64, never preview; retain the original packet snapshot."""
    config = config if config is not None else DecoderConfig()
    processed = ProcessedEvent(packet=event)
    protocol = processed.packet.application.protocol
    if isinstance(protocol, str) and protocol.upper() == "HTTP":
        http_result = decode_http(processed.packet.application, config, charset=charset)
        processed.decoded["http"] = http_result.to_dict()
        processed.decode_status = http_result.status
        processed.errors.extend(http_result.errors)
        if http_result.errors:
            processed.reason = "; ".join(error.message for error in http_result.errors)
        return processed
    raw = processed.packet.payload.base64

    if raw is None:
        if processed.packet.payload.length == 0:
            result = TextDecodeResult(None, None, DecodeStatus.SKIPPED)
        else:
            result = TextDecodeResult(
                None, None, DecodeStatus.ERROR,
                [decode_error("missing_raw_payload", "Nonempty payload has no raw Base64 data")],
            )
    elif not isinstance(raw, str):
        result = TextDecodeResult(
            None, None, DecodeStatus.ERROR,
            [decode_error("invalid_payload_base64", "Payload Base64 must be a string")],
        )
    elif len(raw) > 4 * ((config.max_input_bytes + 2) // 3):
        # Bound Base64 allocation before materializing the raw byte payload.
        result = limit_result(
            config, "input_limit_exceeded",
            f"Base64 payload exceeds the encoding size for {config.max_input_bytes} input bytes",
        )
    else:
        try:
            payload = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            result = TextDecodeResult(
                None, None, DecodeStatus.ERROR,
                [decode_error("invalid_payload_base64", "Payload contains invalid Base64 data")],
            )
        else:
            result = decode_text(payload, config, charset=charset)

    processed.decoded["payload"] = {
        "text": result.text,
        "charset": result.charset,
        "status": result.status.value,
    }
    processed.decode_status = result.status
    processed.errors.extend(result.errors)
    if result.errors:
        processed.reason = "; ".join(error.message for error in result.errors)
    return processed
