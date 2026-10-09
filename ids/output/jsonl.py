import json
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, TextIO


class JsonSerializable(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


class JsonlWriter:
    def __init__(self, output_path: str | Path, append: bool = False) -> None:
        self.output_path = Path(output_path)
        self.append = append
        self._file: TextIO | None = None

    def __enter__(self) -> "JsonlWriter":
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        mode = "a" if self.append else "w"
        self._file = self.output_path.open(
            mode=mode,
            encoding="utf-8",
            buffering=1,
        )
        return self

    def write(self, event: JsonSerializable | dict[str, Any]) -> None:
        if self._file is None:
            raise RuntimeError("JsonlWriter must be used inside a with block")

        line = json.dumps(
            event if isinstance(event, dict) else event.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        )

        self._file.write(line + "\n")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
