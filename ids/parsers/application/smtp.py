import re
from dataclasses import dataclass, field
from typing import Any

from ids.models import ApplicationInfo
from ids.parsers.application.mime import looks_like_mime, parse_mime


SMTP_RESPONSE_LINE = re.compile(
    r"^(?P<code>[2-5][0-9]{2})(?P<separator>[ -])(?P<message>.*)$"
)
SMTP_COMMAND_LINE = re.compile(
    r"^(?P<command>[A-Za-z]+)(?:[ \t]+(?P<argument>.*))?$"
)
SMTP_MAIL_FROM_LINE = re.compile(
    r"^MAIL[ \t]+FROM:[ \t]*(?P<path><[^>]*>|[^ \t]+)"
    r"(?:[ \t]+(?P<parameters>.*))?$",
    re.IGNORECASE,
)
SMTP_RCPT_TO_LINE = re.compile(
    r"^RCPT[ \t]+TO:[ \t]*(?P<path><[^>]*>|[^ \t]+)"
    r"(?:[ \t]+(?P<parameters>.*))?$",
    re.IGNORECASE,
)

SUPPORTED_COMMANDS = {
    "HELO",
    "EHLO",
    "MAIL",
    "RCPT",
    "DATA",
    "RSET",
    "NOOP",
    "QUIT",
    "VRFY",
    "EXPN",
    "AUTH",
    "STARTTLS",
}


class SmtpParseError(ValueError):
    pass


@dataclass(slots=True)
class SmtpParseResult:
    application: ApplicationInfo
    complete: bool
    warnings: list[str] = field(default_factory=list)


def _split_lines(payload: bytes) -> tuple[list[str], bool, list[str]]:
    if not payload:
        raise SmtpParseError("SMTP payload is empty")

    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SmtpParseError("SMTP payload is not valid UTF-8") from error

    lines = text.splitlines()

    if not lines or any(not line for line in lines):
        raise SmtpParseError("SMTP line is empty")

    complete = text.endswith("\n")
    warnings: list[str] = []

    if not complete:
        warnings.append("SMTP line is missing its line terminator")

    return lines, complete, warnings


def _strip_path_brackets(path: str) -> str:
    if path.startswith("<") and path.endswith(">"):
        return path[1:-1]
    return path


def _parse_path_command(
    line: str,
    pattern: re.Pattern[str],
    command_name: str,
) -> dict[str, Any] | None:
    match = pattern.fullmatch(line)

    if match is None:
        return None

    path = match.group("path")
    raw_parameters = match.group("parameters")
    parameters = raw_parameters.split() if raw_parameters else []

    return {
        "command": command_name,
        "argument": path,
        "mailbox": _strip_path_brackets(path),
        "parameters": parameters,
        "raw_line": line,
    }


def _parse_command_line(line: str) -> dict[str, Any]:
    mail_from = _parse_path_command(
        line,
        SMTP_MAIL_FROM_LINE,
        "MAIL FROM",
    )
    if mail_from is not None:
        return mail_from

    rcpt_to = _parse_path_command(
        line,
        SMTP_RCPT_TO_LINE,
        "RCPT TO",
    )
    if rcpt_to is not None:
        return rcpt_to

    match = SMTP_COMMAND_LINE.fullmatch(line)

    if match is None:
        raise SmtpParseError(f"Malformed SMTP command line: {line!r}")

    command = match.group("command").upper()
    argument = match.group("argument")

    if command not in SUPPORTED_COMMANDS:
        raise SmtpParseError(f"Unsupported SMTP command: {command}")

    if command in {"MAIL", "RCPT"}:
        expected_form = "MAIL FROM:<address>" if command == "MAIL" else "RCPT TO:<address>"
        raise SmtpParseError(
            f"Malformed SMTP {command} command; expected {expected_form}"
        )

    if command in {"HELO", "EHLO"}:
        if argument is None or not argument.strip():
            raise SmtpParseError(f"SMTP {command} command requires a domain")

        domain = argument.strip()
        if any(character.isspace() for character in domain):
            raise SmtpParseError(
                f"SMTP {command} command contains an invalid domain"
            )

        return {
            "command": command,
            "argument": domain,
            "domain": domain,
            "raw_line": line,
        }

    return {
        "command": command,
        "argument": argument.strip() if argument else None,
        "raw_line": line,
    }


def _parse_commands(
    lines: list[str],
    complete: bool,
) -> ApplicationInfo:
    commands = [_parse_command_line(line) for line in lines]
    first_command = commands[0]

    fields: dict[str, Any] = {
        "command": first_command["command"],
        "argument": first_command.get("argument"),
        "commands": commands,
        "command_count": len(commands),
        "message_complete": complete,
    }

    if "domain" in first_command:
        fields["domain"] = first_command["domain"]

    if "mailbox" in first_command:
        fields["mailbox"] = first_command["mailbox"]
        fields["parameters"] = first_command["parameters"]

    return ApplicationInfo(
        protocol="SMTP",
        kind="command",
        fields=fields,
    )


def _parse_response_lines(
    lines: list[str],
    payload_complete: bool,
    warnings: list[str],
) -> tuple[ApplicationInfo, bool]:
    responses: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    responses_complete = True

    for line in lines:
        match = SMTP_RESPONSE_LINE.fullmatch(line)

        if match is None:
            raise SmtpParseError(f"Malformed SMTP response line: {line!r}")

        status_code = int(match.group("code"))
        separator = match.group("separator")
        message = match.group("message")

        if current is None:
            current = {
                "status_code": status_code,
                "messages": [],
                "multiline": separator == "-",
                "complete": False,
            }
        elif current["status_code"] != status_code:
            current["complete"] = False
            responses.append(current)
            warnings.append(
                "SMTP multiline response changed status code before termination"
            )
            responses_complete = False
            current = {
                "status_code": status_code,
                "messages": [],
                "multiline": separator == "-",
                "complete": False,
            }

        current["messages"].append(message)

        if separator == " ":
            current["complete"] = True
            responses.append(current)
            current = None

    if current is not None:
        responses.append(current)
        warnings.append(
            "SMTP multiline response is missing its terminating line"
        )
        responses_complete = False

    complete = payload_complete and responses_complete
    first_response = responses[0]
    fields: dict[str, Any] = {
        "status_code": first_response["status_code"],
        "message": "\n".join(first_response["messages"]),
        "messages": first_response["messages"],
        "multiline": first_response["multiline"],
        "responses": responses,
        "response_count": len(responses),
        "message_complete": complete,
    }

    return (
        ApplicationInfo(
            protocol="SMTP",
            kind="response",
            fields=fields,
        ),
        complete,
    )


def parse_smtp(payload: bytes) -> SmtpParseResult:
    if looks_like_mime(payload):
        mime = parse_mime(payload, smtp_data=True)
        return SmtpParseResult(mime.application, mime.complete, mime.warnings)
    lines, payload_complete, warnings = _split_lines(payload)

    if SMTP_RESPONSE_LINE.fullmatch(lines[0]):
        application, complete = _parse_response_lines(
            lines,
            payload_complete,
            warnings,
        )
    else:
        application = _parse_commands(lines, payload_complete)
        complete = payload_complete

    return SmtpParseResult(
        application=application,
        complete=complete,
        warnings=warnings,
    )
