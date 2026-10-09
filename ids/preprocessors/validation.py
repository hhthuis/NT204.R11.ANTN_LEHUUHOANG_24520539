"""Validate event metadata without changing raw values or authorizing tracking."""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address

from ids.models import ApplicationInfo, CaptureSource, NetworkInfo, PacketEvent, PayloadInfo, TransportInfo
from ids.processing_models import (
    PreprocessStatus, ProcessedEvent, ProcessingAction, ProcessingError, ProcessingStage,
)


APPLICATION_PROTOCOLS = {"HTTP", "DNS", "SMTP", "MIME", "UNKNOWN"}
TCP_FLAGS = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS"}


@dataclass(slots=True)
class ValidationResult:
    status: PreprocessStatus
    tracking_eligible: bool
    errors: list[ProcessingError] = field(default_factory=list)

    @property
    def reason(self) -> str | None:
        return "; ".join(error.message for error in self.errors) or None


def _integer(value: object, minimum: int, maximum: int | None = None) -> bool:
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def _protocol(value: object) -> str | None:
    # Temporary spelling for validation only. Normalization writes its own fields.
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def validate_packet(packet: PacketEvent) -> ValidationResult:
    """Check required tracking metadata and optional data quality safely.

    INVALID means required data is absent/malformed. PARTIAL means optional
    data is questionable, parsing was partial, or a protocol is unsupported.
    tracking_eligible only means metadata can support later tracking; unsupported
    network/transport, noninitial fragments and unsafe TCP flags still block it.
    Decode status is independent, and empty-payload handshake packets are valid.
    """
    errors: list[ProcessingError] = []
    invalid = False
    eligible = True

    def report(code: str, message: str, *, required: bool = False, block: bool = False) -> None:
        nonlocal invalid, eligible
        errors.append(ProcessingError(ProcessingStage.PREPROCESS, "validation_" + code, message))
        invalid |= required
        eligible &= not (required or block)

    if not isinstance(packet, PacketEvent):
        report("invalid_packet_event", "Validation requires a PacketEvent", required=True)
        return ValidationResult(PreprocessStatus.INVALID, False, errors)

    if not _integer(packet.packet_id, 1):
        report("invalid_packet_id", "packet_id must be a positive integer", required=True)
    if not _integer(packet.captured_length, 0):
        report("invalid_captured_length", "captured_length must be a nonnegative integer", required=True)
    if packet.wire_length is not None:
        if not _integer(packet.wire_length, 0) or (
            _integer(packet.captured_length, 0) and packet.wire_length < packet.captured_length
        ):
            report("invalid_wire_length", "wire_length must be nonnegative and at least captured_length")

    try:
        if not isinstance(packet.timestamp, str) or not packet.timestamp.strip():
            raise ValueError("timestamp must be text")
        timestamp = datetime.fromisoformat(packet.timestamp.strip())
        if timestamp.utcoffset() is None:
            raise ValueError("timestamp has no timezone")
        timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        report("invalid_timestamp", "timestamp must be a valid ISO datetime with timezone convertible to UTC", required=True)

    if not isinstance(packet.source, CaptureSource) or not isinstance(packet.source.name, str) or not packet.source.name.strip():
        report("invalid_capture_source", "Capture source needs a nonempty name")
    elif packet.source.type not in ("pcap", "interface"):
        report("unsupported_capture_source", "Capture source type is not pcap or interface")

    network = packet.network
    if not isinstance(network, NetworkInfo):
        report("missing_network", "Event needs NetworkInfo with IP endpoints", required=True)
    else:
        network_protocol = _protocol(network.protocol)
        if network_protocol is None:
            report("invalid_network_protocol", "Network protocol must be nonempty text", required=True)
        elif network_protocol != "IPV4":
            report("unsupported_network_protocol", "Only IPv4 network events are currently supported", block=True)
        for name in ("src_ip", "dst_ip"):
            raw = getattr(network, name)
            try:
                if not isinstance(raw, str):
                    raise ValueError("IP endpoint must be text")
                address = ip_address(raw.strip())
            except ValueError:
                report("invalid_ip_address", f"network.{name} must be a valid IP address", required=True)
            else:
                if network_protocol == "IPV4" and address.version != 4:
                    report("ip_protocol_mismatch", f"network.{name} is not IPv4 as declared", required=True)
                elif network_protocol == "IPV6" and address.version != 6:
                    report("ip_protocol_mismatch", f"network.{name} is not IPv6 as declared", required=True)
        if network.ttl is not None and not _integer(network.ttl, 0, 255):
            report("invalid_ttl", "IPv4 TTL must be an integer in 0..255")
        if network.fragment_offset is not None:
            if not _integer(network.fragment_offset, 0, 8191):
                report("invalid_fragment_offset", "IPv4 fragment offset must be an integer in 0..8191", block=True)
            elif network.fragment_offset > 0:
                report("noninitial_fragment", "Noninitial IP fragments need reassembly before port-based tracking", block=True)

    transport = packet.transport
    if not isinstance(transport, TransportInfo):
        report("missing_transport", "Event needs TransportInfo with port endpoints", required=True)
    else:
        protocol = _protocol(transport.protocol)
        if protocol is None:
            report("invalid_transport_protocol", "Transport protocol must be nonempty text", required=True)
        elif protocol not in ("TCP", "UDP"):
            report("unsupported_transport_protocol", "Only TCP/UDP transports are currently supported", block=True)
        for name in ("src_port", "dst_port"):
            if not _integer(getattr(transport, name), 0, 65535):
                report("invalid_port", f"transport.{name} must be an integer in 0..65535", required=True)
        if not isinstance(transport.fields, dict):
            report("invalid_transport_fields", "Transport fields must be a dictionary", block=True)
        elif protocol == "TCP":
            flags = transport.fields.get("flags")
            if flags is None:
                report("missing_tcp_flags", "TCP flags are missing; connection state cannot be inferred")
            elif not isinstance(flags, list) or any(_protocol(flag) not in TCP_FLAGS for flag in flags):
                report("invalid_tcp_flags", "TCP flags must be a list of supported flag names", block=True)
            elif len({_protocol(flag) for flag in flags}) != len(flags):
                report("duplicate_tcp_flags", "TCP flag list repeats the same flag")

    payload = packet.payload
    if not isinstance(payload, PayloadInfo):
        report("missing_payload_info", "Payload metadata is missing or has the wrong type")
    else:
        if not _integer(payload.length, 0) or (
            _integer(packet.captured_length, 0) and payload.length > packet.captured_length
        ):
            report("invalid_payload_length", "Payload length must be nonnegative and no larger than captured_length")
        if payload.base64 is not None and not isinstance(payload.base64, str):
            report("invalid_payload_representation", "Raw payload Base64 must be text or null")
        elif _integer(payload.length, 1) and not payload.base64:
            report("missing_raw_payload", "Nonempty payload has no raw Base64 data")
        # Byte/Base64 decoding and size limits belong to Decoder, not validation.

    application = packet.application
    if not isinstance(application, ApplicationInfo):
        report("missing_application_info", "Application metadata is missing or has the wrong type")
    else:
        protocol = _protocol(application.protocol)
        if protocol is None:
            report("invalid_application_protocol", "Application protocol must be nonempty text")
        elif protocol not in APPLICATION_PROTOCOLS:
            report("unsupported_application_protocol", "Application protocol is not recognized; valid transport may still be tracked")
        if not isinstance(application.fields, dict):
            report("invalid_application_fields", "Application fields must be a dictionary")

    parse_status = _protocol(packet.parse_status)
    if parse_status == "MALFORMED":
        report("malformed_packet", "Parser marked the packet malformed", required=True)
    elif parse_status == "UNSUPPORTED":
        report("unsupported_packet", "Parser marked the packet unsupported", block=True)
    elif parse_status == "PARTIAL":
        report("partial_packet", "Parser marked the packet partial")
    elif parse_status != "OK":
        report("invalid_parse_status", "Parser status must be ok/partial/malformed/unsupported", required=True)
    if isinstance(packet.errors, list) and any(
        _protocol(getattr(error, "stage", None)) in ("NETWORK", "TRANSPORT")
        for error in packet.errors
    ):
        report("unsafe_lower_layer_parse", "Network/transport parsing reported errors; endpoints cannot be trusted", block=True)

    status = PreprocessStatus.INVALID if invalid else PreprocessStatus.PARTIAL if errors else PreprocessStatus.VALID
    return ValidationResult(status, eligible, errors)


def validate_event(event: ProcessedEvent) -> ProcessedEvent:
    """Return a detached event with validation metadata; normalization comes next.

    Repeat calls replace this validator's prior errors instead of accumulating
    duplicates. Existing decode errors/status/reason and raw packet are retained.
    Always clear flow association and keep skip_tracking until the complete
    preprocessor normalizes data and applies policy in later tasks.
    """
    processed = deepcopy(event)
    result = validate_packet(processed.packet)
    processed.errors = [
        error for error in processed.errors
        if not (error.stage == ProcessingStage.PREPROCESS and error.code.startswith("validation_"))
    ]
    processed.errors.extend(result.errors)
    processed.preprocess_status = result.status
    processed.processing_action = ProcessingAction.SKIP_TRACKING
    processed.flow = None
    # Remove old structured reason fragments before rebuilding from current
    # errors. This keeps caller notes and does not retain resolved errors.
    old_fragments = {
        part for error in event.errors for part in error.message.split("; ")
    }
    notes = [part for part in (event.reason or "").split("; ") if part and part not in old_fragments]
    messages = notes + [error.message for error in processed.errors]
    processed.reason = "; ".join(dict.fromkeys(messages)) or None
    return processed
