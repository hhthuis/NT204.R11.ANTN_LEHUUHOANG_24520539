from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from ids.config import (
    CapacityPolicy,
    ConfigError,
    DecodeLimitPolicy,
    DecoderConfig,
    EventPolicy,
    InvalidBytesPolicy,
    PreprocessorConfig,
    ProcessingConfig,
    TrackerConfig,
    load_config,
)


def write_config(tmp_path, content: str) -> Path:
    path = tmp_path / "processing.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_default_file_matches_builtin_defaults():
    path = Path(__file__).resolve().parents[2] / "config" / "default.toml"

    assert load_config(path) == load_config() == ProcessingConfig()


def test_partial_overrides_keep_defaults_and_do_not_change_later_loads(tmp_path):
    path = write_config(tmp_path, '''
[decoder]
default_charset = "UTF8"
invalid_bytes_policy = "strict"
max_input_bytes = 2048
limit_policy = "error"
[preprocessor]
invalid_event_policy = "mark"
unsupported_event_policy = "skip"
[tracker]
tcp_idle_timeout = 60
udp_idle_timeout = 0.5
expiry_check_interval = 0.1
max_active_flows = 20
capacity_policy = "skip_new"
''')
    config = load_config(path)

    assert config.decoder.default_charset == "utf-8"
    assert config.decoder.max_input_bytes == 2048
    assert config.decoder.max_output_bytes == load_config().decoder.max_output_bytes
    assert config.decoder.invalid_bytes_policy is InvalidBytesPolicy.STRICT
    assert config.decoder.limit_policy is DecodeLimitPolicy.ERROR
    assert config.preprocessor.invalid_event_policy is EventPolicy.MARK
    assert config.preprocessor.unsupported_event_policy is EventPolicy.SKIP
    assert config.tracker.tcp_idle_timeout == 60.0
    assert config.tracker.udp_idle_timeout == 0.5
    assert config.tracker.expiry_check_interval == 0.1
    assert config.tracker.max_active_flows == 20
    assert config.tracker.capacity_policy is CapacityPolicy.SKIP_NEW
    assert load_config().decoder.max_input_bytes == 1_048_576
    with pytest.raises(FrozenInstanceError):
        config.tracker.max_active_flows = 0


def test_empty_config_uses_all_defaults(tmp_path):
    assert load_config(write_config(tmp_path, "")) == load_config()


@pytest.mark.parametrize("alias, expected", [("ASCII", "ascii"), ("UTF8", "utf-8")])
def test_supported_charset_aliases_are_canonicalized(tmp_path, alias, expected):
    path = write_config(tmp_path, f'[decoder]\ndefault_charset = "{alias}"')
    config = load_config(path)
    assert config.decoder.default_charset == expected


@pytest.mark.parametrize("value", ['"utf-16"', '"made-up-charset"', '123'])
def test_unsupported_or_non_string_charset_is_rejected(tmp_path, value):
    with pytest.raises(ConfigError, match="decoder.default_charset"):
        load_config(write_config(tmp_path, f"[decoder]\ndefault_charset = {value}"))


@pytest.mark.parametrize("section, setting, value", [
    ("decoder", "max_input_bytes", "0"),
    ("decoder", "max_input_bytes", "true"),
    ("decoder", "max_output_bytes", "-1"),
    ("decoder", "max_output_bytes", "1.5"),
    ("tracker", "max_active_flows", "0"),
    ("tracker", "max_active_flows", "true"),
    ("tracker", "max_active_flows", "2.5"),
    ("tracker", "tcp_idle_timeout", "0"),
    ("tracker", "tcp_idle_timeout", "true"),
    ("tracker", "tcp_idle_timeout", '"180"'),
    ("tracker", "tcp_idle_timeout", "nan"),
    ("tracker", "udp_idle_timeout", "inf"),
    ("tracker", "udp_idle_timeout", "-1.0"),
    ("tracker", "expiry_check_interval", "0"),
])
def test_invalid_limits_and_timeouts_are_rejected(tmp_path, section, setting, value):
    with pytest.raises(ConfigError, match=rf"{section}\.{setting}"):
        load_config(write_config(tmp_path, f"[{section}]\n{setting} = {value}"))


@pytest.mark.parametrize("section, setting, value", [
    ("decoder", "invalid_bytes_policy", '"ignore"'),
    ("decoder", "limit_policy", '"truncate"'),
    ("preprocessor", "invalid_event_policy", '"track"'),
    ("preprocessor", "unsupported_event_policy", "false"),
    ("tracker", "capacity_policy", '"unlimited"'),
])
def test_invalid_policies_list_allowed_choices(tmp_path, section, setting, value):
    with pytest.raises(ConfigError, match=rf"{section}\.{setting} must be one of"):
        load_config(write_config(tmp_path, f"[{section}]\n{setting} = {value}"))


@pytest.mark.parametrize("content, message", [
    ("[decodre]\nmax_input_bytes=10", "Unknown configuration section: decodre"),
    ("[decoder]\nmax_inpt_bytes=10", "Unknown setting in decoder: max_inpt_bytes"),
    ("decoder=10", "decoder must be a TOML table"),
])
def test_unknown_sections_settings_and_wrong_table_types_are_rejected(
    tmp_path, content, message
):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, content))


@pytest.mark.parametrize("content", [b"[decoder\n", b"\xff"])
def test_malformed_toml_or_invalid_file_encoding_has_readable_error(
    tmp_path, content
):
    path = tmp_path / "broken.toml"
    path.write_bytes(content)
    with pytest.raises(ConfigError, match="Cannot load configuration.*broken.toml"):
        load_config(path)


def test_missing_file_does_not_silently_fall_back_to_defaults(tmp_path):
    with pytest.raises(ConfigError, match="Cannot load configuration.*missing.toml"):
        load_config(tmp_path / "missing.toml")


def test_directory_cannot_be_loaded_as_a_config_file(tmp_path):
    with pytest.raises(ConfigError, match="Cannot load configuration"):
        load_config(tmp_path)


@pytest.mark.parametrize("constructor, settings, message", [
    (DecoderConfig, {"max_input_bytes": True}, "decoder.max_input_bytes"),
    (DecoderConfig, {"default_charset": "\x00"}, "decoder.default_charset"),
    (
        PreprocessorConfig,
        {"invalid_event_policy": "track"},
        "preprocessor.invalid_event_policy",
    ),
    (TrackerConfig, {"tcp_idle_timeout": -1}, "tracker.tcp_idle_timeout"),
    (TrackerConfig, {"tcp_idle_timeout": 10 ** 1000}, "tracker.tcp_idle_timeout"),
])
def test_direct_config_construction_is_validated_too(
    constructor, settings, message
):
    with pytest.raises(ConfigError, match=message):
        constructor(**settings)


@pytest.mark.parametrize("section", ["decoder", "preprocessor", "tracker"])
def test_processing_config_requires_validated_section_models(section):
    with pytest.raises(ConfigError, match=f"{section} must be a"):
        ProcessingConfig(**{section: {}})
