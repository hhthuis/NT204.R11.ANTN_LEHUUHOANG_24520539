"""Compose validation and normalization; policy/CLI/tracking come in later tasks."""

from ids.config import PreprocessorConfig
from ids.preprocessors.normalization import normalize_packet
from ids.preprocessors.validation import validate_event
from ids.processing_models import PreprocessStatus, ProcessedEvent, ProcessingAction, ProcessingStage


def preprocess_event(event: ProcessedEvent, config: PreprocessorConfig | None = None) -> ProcessedEvent:
    """Return a detached normalized event, retaining raw and decode results."""
    # Discard only prior normalization diagnostics before validation rebuilds
    # reason. Resolved issues must not linger on repeated preprocessing.
    processed = validate_event(event)
    processed.errors = [
        error for error in processed.errors
        if not (error.stage == ProcessingStage.PREPROCESS and error.code.startswith("normalization_"))
    ]
    result = normalize_packet(processed.packet, config)
    processed.normalized = result.value or {}
    processed.errors.extend(result.errors)
    if result.errors and processed.preprocess_status != PreprocessStatus.INVALID:
        processed.preprocess_status = PreprocessStatus.PARTIAL
    old_fragments = {part for error in event.errors for part in error.message.split("; ")}
    notes = [part for part in (event.reason or "").split("; ") if part and part not in old_fragments]
    processed.reason = "; ".join(dict.fromkeys(notes + [error.message for error in processed.errors])) or None
    processed.processing_action = ProcessingAction.SKIP_TRACKING
    processed.flow = None
    return processed
