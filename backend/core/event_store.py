from collections import deque
from threading import Lock
from typing import Optional
from backend.core.schema import ThreatEvent


class EventStore:
    def __init__(self, maxlen: int = 1000):
        self._store: deque[dict] = deque(maxlen=maxlen)
        self._lock = Lock()

    def add(self, event: ThreatEvent) -> None:
        with self._lock:
            self._store.appendleft(event.to_dict())

    def get_recent(self, n: int = 100) -> list[dict]:
        with self._lock:
            return list(self._store)[:n]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# Module-level singleton — shared between pipeline and dashboard
event_store = EventStore(maxlen=1000)