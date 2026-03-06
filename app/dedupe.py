from __future__ import annotations

from collections import OrderedDict
from typing import Iterable


class MessageDeduper:
    def __init__(self, max_size: int = 6000) -> None:
        self._max_size = max_size
        self._seen: OrderedDict[str, None] = OrderedDict()

    def clear(self) -> None:
        self._seen.clear()

    def seed(self, fingerprints: Iterable[str]) -> None:
        for fp in fingerprints:
            self.add(fp)

    def add(self, fingerprint: str) -> bool:
        if fingerprint in self._seen:
            self._seen.move_to_end(fingerprint)
            return False
        self._seen[fingerprint] = None
        while len(self._seen) > self._max_size:
            self._seen.popitem(last=False)
        return True

