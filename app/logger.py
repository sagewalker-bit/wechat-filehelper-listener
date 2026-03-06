from __future__ import annotations

import json
from pathlib import Path
import threading
from datetime import datetime
from typing import Any


class JsonlLogger:
    def __init__(self, file_path: Path) -> None:
        self._file_path = file_path
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, event: str, **fields: Any) -> None:
        payload = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "event": event,
            **fields,
        }
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            with self._file_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

