"""Validated, immutable configuration contracts for Lab 2 processing.

load_config() uses built-in defaults. A TOML file may override individual
settings; omitted sections/settings retain defaults. The modules consuming
these settings and their CLI wiring are implemented in later tasks.
"""

import codecs
import math
import tomllib
from dataclasses import dataclass, field, fields
from enum import StrEnum
from pathlib import Path
from typing import Any, TypeVar


class ConfigError(ValueError):
    """An unreadable file or unsupported configuration setting."""


class InvalidBytesPolicy(StrEnum):
    REPLACE = "replace"
    STRICT = "strict"


class DecodeLimitPolicy(StrEnum):
    SKIP = "skip"
    ERROR = "error"


class EventPolicy(StrEnum):
    MARK = "mark"
    SKIP = "skip"


class CapacityPolicy(StrEnum):
    EVICT_OLDEST = "evict_oldest"
    SKIP_NEW = "skip_new"


def _positive_integer(name: str, value: Any) -> None:
    # bool is a subclass of int but is not a meaningful size/count setting.
    if type(value) is not int or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")


def _positive_seconds(name: str, value: Any) -> float:
    if type(value) not in (int, float):
        raise ConfigError(f"{name} must be a positive finite number of seconds")
    try:
        seconds = float(value)
    except OverflowError as error:
        raise ConfigError(f"{name} must be finite") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise ConfigError(f"{name} must be a positive finite number of seconds")
    return seconds


EnumType = TypeVar("EnumType", bound=StrEnum)


def _policy(name: str, value: Any, enum_type: type[EnumType]) -> EnumType:
    try:
        return enum_type(value)
    except (ValueError, TypeError) as error:
        choices = ", ".join(item.value for item in enum_type)
        raise ConfigError(f"{name} must be one of: {choices}") from error


@dataclass(frozen=True, slots=True)
class DecoderConfig:
    default_charset: str = "utf-8"
    invalid_bytes_policy: InvalidBytesPolicy = InvalidBytesPolicy.REPLACE
    max_input_bytes: int = 1_048_576
    max_output_bytes: int = 1_048_576
    limit_policy: DecodeLimitPolicy = DecodeLimitPolicy.SKIP

    def __post_init__(self) -> None:
        if not isinstance(self.default_charset, str):
            raise ConfigError("decoder.default_charset must be ASCII or UTF-8")
        try:
            charset = codecs.lookup(self.default_charset).name
        except (LookupError, ValueError) as error:
            raise ConfigError(
                "decoder.default_charset must be ASCII or UTF-8"
            ) from error
        if charset not in ("ascii", "utf-8"):
            raise ConfigError("decoder.default_charset must be ASCII or UTF-8")
        object.__setattr__(self, "default_charset", charset)
        for name in ("max_input_bytes", "max_output_bytes"):
            _positive_integer(f"decoder.{name}", getattr(self, name))
        for name, enum_type in (
            ("invalid_bytes_policy", InvalidBytesPolicy),
            ("limit_policy", DecodeLimitPolicy),
        ):
            object.__setattr__(
                self, name, _policy(f"decoder.{name}", getattr(self, name), enum_type)
            )


@dataclass(frozen=True, slots=True)
class PreprocessorConfig:
    invalid_event_policy: EventPolicy = EventPolicy.SKIP
    unsupported_event_policy: EventPolicy = EventPolicy.MARK

    def __post_init__(self) -> None:
        for name in ("invalid_event_policy", "unsupported_event_policy"):
            object.__setattr__(
                self,
                name,
                _policy(f"preprocessor.{name}", getattr(self, name), EventPolicy),
            )


@dataclass(frozen=True, slots=True)
class TrackerConfig:
    tcp_idle_timeout: float = 180.0
    udp_idle_timeout: float = 30.0
    expiry_check_interval: float = 1.0
    max_active_flows: int = 10_000
    capacity_policy: CapacityPolicy = CapacityPolicy.EVICT_OLDEST

    def __post_init__(self) -> None:
        for name in ("tcp_idle_timeout", "udp_idle_timeout", "expiry_check_interval"):
            object.__setattr__(
                self, name, _positive_seconds(f"tracker.{name}", getattr(self, name))
            )
        _positive_integer("tracker.max_active_flows", self.max_active_flows)
        object.__setattr__(
            self,
            "capacity_policy",
            _policy("tracker.capacity_policy", self.capacity_policy, CapacityPolicy),
        )


@dataclass(frozen=True, slots=True)
class ProcessingConfig:
    decoder: DecoderConfig = field(default_factory=DecoderConfig)
    preprocessor: PreprocessorConfig = field(default_factory=PreprocessorConfig)
    tracker: TrackerConfig = field(default_factory=TrackerConfig)

    def __post_init__(self) -> None:
        for name, model in (
            ("decoder", DecoderConfig),
            ("preprocessor", PreprocessorConfig),
            ("tracker", TrackerConfig),
        ):
            if not isinstance(getattr(self, name), model):
                raise ConfigError(f"{name} must be a {model.__name__} instance")


SectionType = TypeVar("SectionType")


def _section(
    data: dict[str, Any], name: str, model: type[SectionType]
) -> SectionType:
    settings = data.get(name, {})
    if not isinstance(settings, dict):
        raise ConfigError(f"{name} must be a TOML table")
    allowed = {item.name for item in fields(model)}
    unknown = sorted(set(settings) - allowed)
    if unknown:
        raise ConfigError(f"Unknown setting in {name}: {', '.join(unknown)}")
    return model(**settings)


def load_config(path: str | Path | None = None) -> ProcessingConfig:
    """Load partial overrides, rejecting bad settings and silent typos."""
    if path is None:
        return ProcessingConfig()

    config_path = Path(path)
    try:
        with config_path.open("rb") as source:
            data = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError, UnicodeError) as error:
        raise ConfigError(
            f"Cannot load configuration '{config_path}': {error}"
        ) from error

    unknown = sorted(set(data) - {"decoder", "preprocessor", "tracker"})
    if unknown:
        raise ConfigError(f"Unknown configuration section: {', '.join(unknown)}")
    return ProcessingConfig(
        decoder=_section(data, "decoder", DecoderConfig),
        preprocessor=_section(data, "preprocessor", PreprocessorConfig),
        tracker=_section(data, "tracker", TrackerConfig),
    )
