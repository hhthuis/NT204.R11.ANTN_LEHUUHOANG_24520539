"""Authorize tracking only after validation, normalization and event policies."""

from datetime import datetime, timezone
from ipaddress import ip_address

from ids.config import EventPolicy, PreprocessorConfig
from ids.models import PacketEvent
from ids.preprocessors.validation import ValidationResult
from ids.processing_models import (
    PreprocessStatus, ProcessedEvent, ProcessingAction, ProcessingError, ProcessingStage,
)


def _safe_normalized_metadata(value: dict) -> bool:
    """Limits can remove a required field even when its raw value was valid."""
    try:
        network, transport = value["network"], value["transport"]
        if network["protocol"] != "IPv4" or transport["protocol"] not in ("TCP", "UDP"):
            return False
        if any(not isinstance(network[key], str) or ip_address(network[key]).version != 4 for key in ("src_ip", "dst_ip")):
            return False
        if any(type(transport[key]) is not int or not 0 <= transport[key] <= 65535 for key in ("src_port", "dst_port")):
            return False
        if type(value["captured_length"]) is not int or value["captured_length"] < 0:
            return False
        timestamp = datetime.fromisoformat(value["timestamp"])
        if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
            return False
        # Missing TCP flags normalize to []; flags rejected by validation or
        # normalization must not be converted into a usable empty list.
        if transport["protocol"] == "TCP" and not isinstance(transport["flags"], list):
            return False
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    return True


def _problem_kind(error: ProcessingError, packet: PacketEvent) -> str | None:
    if error.stage != ProcessingStage.PREPROCESS:
        return None  # Decode failures do not invalidate good flow metadata.
    code = error.code
    if code.startswith(("validation_unsupported_", "normalization_unsupported_")) or code == "validation_noninitial_fragment":
        return "unsupported"
    if code in ("validation_missing_tcp_flags", "validation_duplicate_tcp_flags", "validation_partial_packet"):
        return None
    if isinstance(packet, PacketEvent) and (
        (code == "validation_missing_application_info" and packet.application is None)
        or (code == "validation_missing_payload_info" and packet.payload is None)
    ):
        return None  # Absent optional model is different from a malformed model.
    if code.startswith(("validation_", "normalization_")):
        return "invalid"
    return None


def apply_policy(event: ProcessedEvent, validation: ValidationResult, config: PreprocessorConfig) -> None:
    """Set action on the detached result; skip still retains the event for logs.

    mark may authorize partial events with safe metadata. Neither policy can
    authorize invalid/unsafe endpoints, unsupported transports or fragments.
    Missing optional data and repaired flag spelling do not invoke skip policy.
    """
    kinds = {_problem_kind(error, event.packet) for error in event.errors}
    blocked = False
    for kind, setting in (
        ("invalid", config.invalid_event_policy), ("unsupported", config.unsupported_event_policy),
    ):
        if kind in kinds:
            blocked |= setting == EventPolicy.SKIP
            event.errors.append(ProcessingError(
                ProcessingStage.PREPROCESS, f"policy_{kind}_{setting.value}",
                f"{kind}_event_policy={setting.value}: " + (
                    "skip flow tracking" if setting == EventPolicy.SKIP
                    else "retain marked event; tracking still requires safe supported metadata"
                ),
            ))
    safe = _safe_normalized_metadata(event.normalized)
    if validation.tracking_eligible and not safe:
        event.errors.append(ProcessingError(
            ProcessingStage.PREPROCESS, "policy_unusable_normalized_metadata",
            "Normalized tracking metadata is missing, invalid or over its size limit",
        ))
        if event.preprocess_status != PreprocessStatus.INVALID:
            event.preprocess_status = PreprocessStatus.PARTIAL
    event.processing_action = (
        ProcessingAction.TRACK
        if validation.tracking_eligible and safe and not blocked and event.preprocess_status != PreprocessStatus.INVALID
        else ProcessingAction.SKIP_TRACKING
    )
    event.flow = None  # Authorization is not flow creation.
