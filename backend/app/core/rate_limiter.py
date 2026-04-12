from collections import defaultdict, deque
from threading import Lock
from time import time


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time()
        with self._lock:
            window = self._events[key]
            while window and window[0] <= now - window_seconds:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True
