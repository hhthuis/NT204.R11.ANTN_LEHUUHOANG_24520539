"""Event decoder: HTTP fields, SMTP/MIME body, or raw character decoding.

Processed CLI mode calls this before Preprocessor and FlowTracker.
"""

import base64
import binascii

from ids.config import DecoderConfig
from ids.decoders.http import decode_http
from ids.decoders.mime import decode_mime
from ids.decoders.text import TextDecodeResult, decode_error, decode_text, limit_result
from ids.models import ApplicationInfo, PacketEvent, PayloadInfo
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
    if not isinstance(event, PacketEvent):
        processed.decode_status = DecodeStatus.ERROR
        processed.errors.append(decode_error("invalid_packet_event", "Decoder requires a PacketEvent"))
        processed.reason = processed.errors[0].message
        return processed
    application = processed.packet.application
    protocol = application.protocol if isinstance(application, ApplicationInfo) else None
    if isinstance(protocol, str) and protocol.upper() == "HTTP":
        http_result = decode_http(processed.packet.application, config, charset=charset)
        processed.decoded["http"] = http_result.to_dict()
        processed.decode_status = http_result.status
        processed.errors.extend(http_result.errors)
        if http_result.errors:
            processed.reason = "; ".join(error.message for error in http_result.errors)
        return processed
    if isinstance(protocol, str) and (
        protocol.upper() == "MIME"
        or (protocol.upper() == "SMTP" and processed.packet.application.kind == "message")
    ):
        mime_result = decode_mime(processed.packet.application, config, charset=charset)
        processed.decoded["mime"] = mime_result.to_dict()
        processed.decode_status = mime_result.status
        processed.errors.extend(mime_result.errors)
        if mime_result.errors:
            processed.reason = "; ".join(error.message for error in mime_result.errors)
        return processed
    payload_info = processed.packet.payload
    if not isinstance(payload_info, PayloadInfo):
        if payload_info is None:
            result = TextDecodeResult(None, None, DecodeStatus.SKIPPED)
        else:
            result = TextDecodeResult(None, None, DecodeStatus.ERROR, [
                decode_error("invalid_payload_info", "Payload metadata must be PayloadInfo or null"),
            ])
    else:
        result = _decode_payload(payload_info, config, charset)

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


def _decode_payload(payload_info: PayloadInfo, config: DecoderConfig, charset: str | None) -> TextDecodeResult:
    raw = payload_info.base64

    if raw is None:
        if payload_info.length == 0:
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

    return result
