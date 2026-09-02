from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator


class RateLimiter:
    def __init__(self, delay_ms: int) -> None:
        self.delay_s = max(0, delay_ms) / 1000.0
        self._last = 0.0

    def wait(self) -> None:
        if self.delay_s <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last
        remaining = self.delay_s - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last = time.monotonic()


@contextmanager
def timed() -> Iterator[list[float]]:
    box = [time.monotonic()]
    yield box
    box.append(time.monotonic() - box[0])
