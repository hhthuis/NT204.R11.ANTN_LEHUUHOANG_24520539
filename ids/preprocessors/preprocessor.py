"""Compose validation, normalization and tracking authorization; retain all events."""

from ids.config import PreprocessorConfig
from ids.preprocessors.normalization import normalize_packet
from ids.preprocessors.policy import apply_policy
from ids.preprocessors.validation import validate_event, validate_packet
from ids.processing_models import PreprocessStatus, ProcessedEvent, ProcessingStage


def preprocess_event(event: ProcessedEvent, config: PreprocessorConfig | None = None) -> ProcessedEvent:
    """Return a detached normalized event, retaining raw and decode results."""
    config = config or PreprocessorConfig()
    # Discard prior normalization/policy diagnostics before validation rebuilds
    # reason. Resolved issues must not linger on repeated preprocessing.
    processed = validate_event(event)
    processed.errors = [
        error for error in processed.errors
        if not (error.stage == ProcessingStage.PREPROCESS and error.code.startswith(("normalization_", "policy_")))
    ]
    result = normalize_packet(processed.packet, config)
    processed.normalized = result.value or {}
    processed.errors.extend(result.errors)
    if result.errors and processed.preprocess_status != PreprocessStatus.INVALID:
        processed.preprocess_status = PreprocessStatus.PARTIAL
    apply_policy(processed, validate_packet(processed.packet), config)
    old_fragments = {part for error in event.errors for part in error.message.split("; ")}
    notes = [part for part in (event.reason or "").split("; ") if part and part not in old_fragments]
    processed.reason = "; ".join(dict.fromkeys(notes + [error.message for error in processed.errors])) or None
    return processed
