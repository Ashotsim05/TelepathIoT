from __future__ import annotations

import signal
import sys
from types import FrameType
from typing import Callable

from telepathiot.session import Session


class KillSwitch:
    """Ctrl+C flushes session.json then re-raises KeyboardInterrupt."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._prev: Callable | int | None = None

    def install(self) -> None:
        self._prev = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self._handler)

    def _handler(self, signum: int, frame: FrameType | None) -> None:
        self.session.log_action("runtime", "kill_switch", detail={"signal": signum}, ok=False)
        self.session.mark_aborted()
        self.session.flush()
        sys.stderr.write("\n[telepathiot] interrupted — session flushed.\n")
        raise KeyboardInterrupt
