"""Safe normalization into a separate representation; raw/decoded data is retained."""

import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from ids.config import PreprocessorConfig
from ids.models import ApplicationInfo, NetworkInfo, PacketEvent, TransportInfo
from ids.processing_models import ProcessingError, ProcessingStage


HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
PERCENT_ESCAPE = re.compile(rb"%[0-9a-fA-F]{2}")
INVALID_PERCENT = re.compile(rb"%(?![0-9a-fA-F]{2})")
FLAG_ORDER = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")


@dataclass(slots=True)
class NormalizationResult:
    value: Any
    errors: list[ProcessingError] = field(default_factory=list)


def _error(code: str, message: str) -> NormalizationResult:
    return NormalizationResult(None, [ProcessingError(
        ProcessingStage.PREPROCESS, "normalization_" + code, message,
    )])


def _text(value: Any, config: PreprocessorConfig, context: str) -> NormalizationResult:
    if value is None:
        return NormalizationResult(None)
    if not isinstance(value, str):
        return _error("invalid_text", f"{context} must be text")
    if len(value) > config.max_input_bytes:
        return _error("input_limit_exceeded", f"{context} exceeds normalization input limit")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return _error("invalid_unicode", f"{context} has an invalid Unicode character")
    if size > config.max_input_bytes:
        return _error("input_limit_exceeded", f"{context} exceeds normalization input byte limit")
    return NormalizationResult(value)


def _output(value: str, config: PreprocessorConfig, context: str) -> NormalizationResult:
    if len(value.encode("utf-8")) > config.max_output_bytes:
        return _error("output_limit_exceeded", f"{context} exceeds normalization output byte limit")
    return NormalizationResult(value)


def _merge(errors: list[ProcessingError], incoming: list[ProcessingError]) -> None:
    known = {error.code for error in errors}
    for error in incoming:
        if error.code not in known:
            errors.append(error)
            known.add(error.code)


def _collection(value: Any, config: PreprocessorConfig, context: str, *, output: bool = False) -> NormalizationResult:
    """Bound collections by compact UTF-8 JSON size, including empty entries."""
    limit = config.max_output_bytes if output else config.max_input_bytes
    size = 0
    try:
        for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":")).iterencode(value):
            size += len(chunk.encode("utf-8"))
            if size > limit:
                kind = "output" if output else "input"
                return _error(kind + "_limit_exceeded", f"{context} exceeds normalization {kind} collection byte limit")
    except (TypeError, ValueError, OverflowError, RecursionError):
        return _error("invalid_collection", f"{context} must contain JSON-compatible finite values")
    return NormalizationResult(value)


def normalize_protocol(value: Any, config: PreprocessorConfig | None = None) -> NormalizationResult:
    config = config or PreprocessorConfig()
    result = _text(value, config, "Protocol name")
    if result.value is None:
        return result
    protocol = result.value.strip().upper()
    if not protocol or not re.fullmatch(r"[A-Z][A-Z0-9_-]*", protocol):
        return _error("invalid_protocol", "Protocol name is empty or has invalid characters")
    return _output({"IPV4": "IPv4", "IPV6": "IPv6"}.get(protocol, protocol), config, "Protocol name")


def normalize_ip(value: Any, config: PreprocessorConfig | None = None) -> NormalizationResult:
    config = config or PreprocessorConfig()
    result = _text(value, config, "IP address")
    if result.value is None:
        return result
    try:
        address = ip_address(result.value.strip())
    except ValueError:
        return _error("invalid_ip", "IP address cannot be normalized")
    return _output(str(address), config, "IP address")


def normalize_timestamp(value: Any, config: PreprocessorConfig | None = None) -> NormalizationResult:
    config = config or PreprocessorConfig()
    result = _text(value, config, "Timestamp")
    if result.value is None:
        return result
    try:
        timestamp = datetime.fromisoformat(result.value.strip())
        if timestamp.utcoffset() is None:
            raise ValueError("timezone required")
        canonical = timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return _error("invalid_timestamp", "Timestamp cannot be normalized to UTC")
    return _output(canonical, config, "Timestamp")


def normalize_domain(value: Any, config: PreprocessorConfig | None = None, *, dns_root: bool = False) -> NormalizationResult:
    config = config or PreprocessorConfig()
    result = _text(value, config, "Domain name")
    if result.value is None:
        return result
    domain = result.value.strip()
    if dns_root and domain in ("", "."):
        return _output(".", config, "Domain name")
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain or any(not label for label in domain.split(".")) or any(
        character.isspace() or ord(character) < 33 or ord(character) == 127
        or character in "/\\@:#?[]\ufffd" for character in domain
    ):
        return _error("invalid_domain", "Domain name contains empty labels or unsupported characters")
    # ASCII DNS case normalization only; preserve Unicode labels supplied by
    # the parser rather than applying another IDNA/Unicode mapping here.
    canonical = domain.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    return _output(canonical, config, "Domain name")


def _smtp_domain(value: Any, config: PreprocessorConfig) -> NormalizationResult:
    checked = _text(value, config, "SMTP domain")
    if checked.value is None:
        return checked
    domain = checked.value.strip()
    if domain.startswith("[") and domain.endswith("]"):
        literal = domain[1:-1]
        ipv6 = literal[:5].lower() == "ipv6:"
        address = normalize_ip(literal[5:] if ipv6 else literal, config)
        if address.value is None:
            return address
        if (":" in address.value) != ipv6:
            return _error("invalid_domain", "SMTP address literal has an invalid family tag")
        return _output("[" + ("IPv6:" if ipv6 else "") + address.value + "]", config, "SMTP domain")
    return normalize_domain(domain, config)


def normalize_headers(value: Any, config: PreprocessorConfig | None = None) -> NormalizationResult:
    config = config or PreprocessorConfig()
    if value is None:
        return NormalizationResult(None)
    if not isinstance(value, dict):
        return _error("invalid_headers", "Headers must be a dictionary")
    checked = _collection(value, config, "Headers")
    if checked.errors:
        return checked
    if len(value) > config.max_input_bytes:
        return _error("input_limit_exceeded", "Header collection exceeds normalization input limit")
    normalized: dict[str, list[str]] = {}
    input_size = output_size = 0
    for name, raw_values in value.items():
        checked = _text(name, config, "Header name")
        if checked.value is None:
            return checked if checked.errors else _error("invalid_headers", "Header name cannot be null")
        key = checked.value.strip(" \t").lower()
        if not HEADER_NAME.fullmatch(key):
            return _error("invalid_headers", "Header name contains invalid characters")
        values = raw_values if isinstance(raw_values, list) else [raw_values]
        if len(values) > config.max_input_bytes:
            return _error("input_limit_exceeded", "Header value collection exceeds normalization input limit")
        input_size += len(name.encode("utf-8"))
        output_size += len(key.encode("utf-8")) if key not in normalized else 0
        for item in values:
            checked = _text(item, config, "Header value")
            if checked.value is None:
                return checked if checked.errors else _error("invalid_headers", "Header value cannot be null")
            input_size += len(item.encode("utf-8"))
            output_size += len(item.encode("utf-8"))
        if input_size > config.max_input_bytes:
            return _error("input_limit_exceeded", "Headers exceed normalization input byte limit")
        if output_size > config.max_output_bytes:
            return _error("output_limit_exceeded", "Headers exceed normalization output byte limit")
        normalized.setdefault(key, []).extend(values)
    return _collection(normalized, config, "Headers", output=True)


def normalize_flags(value: Any, config: PreprocessorConfig | None = None) -> NormalizationResult:
    config = config or PreprocessorConfig()
    if value is None:
        return NormalizationResult(None)
    if not isinstance(value, list):
        return _error("invalid_tcp_flags", "TCP flags must be a list")
    checked = _collection(value, config, "TCP flags")
    if checked.errors:
        return checked
    if len(value) > config.max_input_bytes:
        return _error("input_limit_exceeded", "TCP flags exceed normalization input limit")
    flags = set()
    input_size = 0
    for item in value:
        checked = _text(item, config, "TCP flag")
        if checked.value is None:
            return checked if checked.errors else _error("invalid_tcp_flags", "TCP flag cannot be null")
        flag = checked.value.strip().upper()
        if flag not in FLAG_ORDER:
            return _error("invalid_tcp_flags", "TCP flag name is not supported")
        input_size += len(item.encode("utf-8"))
        flags.add(flag)
    if input_size > config.max_input_bytes:
        return _error("input_limit_exceeded", "TCP flags exceed normalization input byte limit")
    ordered = [flag for flag in FLAG_ORDER if flag in flags]
    if sum(len(flag) for flag in ordered) > config.max_output_bytes:
        return _error("output_limit_exceeded", "TCP flags exceed normalization output byte limit")
    return _collection(ordered, config, "TCP flags", output=True)


def normalize_uri(value: Any, config: PreprocessorConfig | None = None) -> NormalizationResult:
    """Canonical percent spelling only; never unquote, rewrite '+', or collapse paths.

    String utility input is UTF-8. The HTTP adapter recovers parser target bytes
    as Latin-1. Non-ASCII wire bytes are percent-represented, without guessing
    a charset. Query splitting happens on literal separators, not decoded ones.
    """
    config = config or PreprocessorConfig()
    if not isinstance(value, (str, bytes)):
        return _error("invalid_uri", "HTTP target must be text or bytes")
    if len(value) > config.max_input_bytes:
        return _error("input_limit_exceeded", "HTTP target exceeds normalization input limit")
    try:
        raw = value.encode("utf-8") if isinstance(value, str) else value
    except UnicodeEncodeError:
        return _error("invalid_unicode", "HTTP target contains invalid Unicode")
    if len(raw) > config.max_input_bytes:
        return _error("input_limit_exceeded", "HTTP target exceeds normalization input byte limit")
    if not raw or any(byte <= 32 or byte == 127 for byte in raw) or b"#" in raw:
        return _error("invalid_uri", "HTTP target is empty or contains whitespace/control/fragment")
    if INVALID_PERCENT.search(raw):
        return _error("invalid_percent_encoding", "HTTP target contains an invalid percent escape")
    canonical = PERCENT_ESCAPE.sub(lambda match: match[0].upper(), raw)
    target = "".join(chr(byte) if byte < 128 else f"%{byte:02X}" for byte in canonical)
    if len(target) > config.max_output_bytes:
        return _error("output_limit_exceeded", "HTTP target exceeds normalization output byte limit")
    if target == "*":
        form, path, query = "asterisk", "*", None
    elif target.startswith("/"):
        path, separator, query = target.partition("?")
        form, query = "origin", query if separator else None
    elif re.match(r"(?i)^https?://", target):
        try:
            parts = urlsplit(target)
            if not parts.hostname or parts.port is not None and not 0 <= parts.port <= 65535:
                raise ValueError("invalid authority")
        except ValueError:
            return _error("invalid_uri", "Absolute HTTP target has an invalid authority")
        form, path = "absolute", parts.path
        query = parts.query if "?" in target else None
    elif re.fullmatch(r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):[0-9]+", target):
        port_digits = target.rsplit(":", 1)[1].lstrip("0") or "0"
        if len(port_digits) > 5 or int(port_digits) > 65535:
            return _error("invalid_uri", "CONNECT target has an invalid port")
        form, path, query = "authority", None, None
    else:
        return _error("unsupported_uri_form", "HTTP target form is unsupported")
    return NormalizationResult({"target": target, "path": path, "query": query, "target_form": form})


def normalize_packet(packet: PacketEvent, config: PreprocessorConfig | None = None) -> NormalizationResult:
    """Normalize selected metadata; fields outside this view remain in raw/decoded."""
    config = config or PreprocessorConfig()
    if not isinstance(packet, PacketEvent):
        return _error("invalid_packet_event", "Normalization requires a PacketEvent")
    errors: list[ProcessingError] = []

    def use(result: NormalizationResult):
        _merge(errors, result.errors)
        return result.value

    def port(value):
        return value if type(value) is int and 0 <= value <= 65535 else None

    network = None
    if isinstance(packet.network, NetworkInfo):
        network = {
            "protocol": use(normalize_protocol(packet.network.protocol, config)),
            "src_ip": use(normalize_ip(packet.network.src_ip, config)),
            "dst_ip": use(normalize_ip(packet.network.dst_ip, config)),
        }
    transport = None
    if isinstance(packet.transport, TransportInfo):
        protocol = use(normalize_protocol(packet.transport.protocol, config))
        raw_flags = packet.transport.fields.get("flags") if isinstance(packet.transport.fields, dict) else None
        transport = {
            "protocol": protocol, "src_port": port(packet.transport.src_port),
            "dst_port": port(packet.transport.dst_port),
            "flags": use(normalize_flags(raw_flags, config)) if protocol == "TCP" else None,
        }
    application = None
    if isinstance(packet.application, ApplicationInfo):
        raw_app = packet.application
        protocol = use(normalize_protocol(raw_app.protocol, config))
        fields = raw_app.fields if isinstance(raw_app.fields, dict) else {}
        normalized_fields = {}
        if protocol == "HTTP":
            normalized_fields["headers"] = use(normalize_headers(fields.get("headers"), config))
            if raw_app.kind == "request":
                normalized_fields["method"] = use(normalize_protocol(fields.get("method"), config))
                target = fields.get("target")
                try:
                    raw_target = target.encode("latin-1") if isinstance(target, str) and len(target) <= config.max_input_bytes else target
                except UnicodeEncodeError:
                    uri = _error("invalid_uri", "Parser target must preserve wire bytes as Latin-1")
                else:
                    uri = normalize_uri(raw_target, config)
                normalized_fields["uri"] = use(uri)
        elif protocol == "DNS":
            for section in ("questions", "answers", "authorities", "additionals"):
                records = fields.get(section)
                if records is None:
                    normalized_fields[section] = None
                elif not isinstance(records, list):
                    normalized_fields[section] = use(_error("invalid_dns_records", f"DNS {section} must be a list"))
                elif (checked := _collection(records, config, "DNS records")).errors:
                    normalized_fields[section] = use(checked)
                else:
                    normalized_records = []
                    for record in records:
                        if not isinstance(record, dict):
                            normalized_records.append(use(_error("invalid_dns_record", "DNS record must be a dictionary")))
                            continue
                        item = deepcopy(record)
                        item["name"] = use(normalize_domain(record.get("name"), config, dns_root=True))
                        for key in ("type", "class"):
                            if key in record:
                                item[key] = use(normalize_protocol(record[key], config))
                        if "data" in record and item.get("type") in ("CNAME", "NS", "PTR", "DNAME"):
                            item["data"] = use(normalize_domain(record.get("data"), config, dns_root=True))
                        elif "data" in record and item.get("type") in ("A", "AAAA"):
                            item["data"] = use(normalize_ip(record.get("data"), config))
                        normalized_records.append(item)
                    normalized_fields[section] = use(_collection(normalized_records, config, "DNS records", output=True))
        elif protocol == "SMTP" and raw_app.kind == "command":
            commands = fields.get("commands")
            if not isinstance(commands, list):
                commands = [fields]
            if (checked := _collection(commands, config, "SMTP commands")).errors:
                normalized_fields["commands"] = use(checked)
            else:
                normalized_commands = []
                for command in commands:
                    if not isinstance(command, dict):
                        normalized_commands.append(use(_error("invalid_smtp_command", "SMTP command must be a dictionary")))
                        continue
                    name = command.get("command")
                    checked = _text(name, config, "SMTP command")
                    name = use(checked)
                    name = use(_output(" ".join(name.strip().upper().split()), config, "SMTP command")) if name else None
                    item = {"command": name}
                    if name in ("HELO", "EHLO"):
                        item["domain"] = use(_smtp_domain(command.get("domain"), config))
                    elif name in ("MAIL FROM", "RCPT TO"):
                        mailbox = use(_text(command.get("mailbox"), config, "SMTP mailbox"))
                        if mailbox:
                            local, at, domain = mailbox.rpartition("@")
                            normalized_domain = use(_smtp_domain(domain, config)) if at and local else None
                            if normalized_domain is None:
                                mailbox = use(_error("invalid_mailbox", "SMTP mailbox needs a local part and domain"))
                            else:
                                mailbox = use(_output(local + "@" + normalized_domain, config, "SMTP mailbox"))
                        item["mailbox"] = mailbox
                    else:
                        item["argument"] = deepcopy(command.get("argument"))
                    normalized_commands.append(item)
                normalized_fields["commands"] = use(_collection(normalized_commands, config, "SMTP commands", output=True))
        elif protocol in ("SMTP", "MIME") and raw_app.kind == "message":
            normalized_fields["headers"] = use(normalize_headers(fields.get("headers"), config))
        application = {"protocol": protocol, "kind": raw_app.kind, "fields": normalized_fields}
    value = {
        "timestamp": use(normalize_timestamp(packet.timestamp, config)),
        "captured_length": packet.captured_length if type(packet.captured_length) is int and packet.captured_length >= 0 else None,
        "network": network, "transport": transport, "application": application,
    }
    return NormalizationResult(value, errors)
