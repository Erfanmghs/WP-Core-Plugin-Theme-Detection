"""Step-by-step scan progress for interactive CLI use."""
from __future__ import annotations

import sys
from typing import TextIO


class Progress:
    """Prints phased progress to stderr so users know the scan is still running."""

    def __init__(self, enabled: bool = True, stream: TextIO = sys.stderr) -> None:
        self.enabled = enabled
        self.stream = stream
        self._step = 0

    def banner(self, target: str, profile: str) -> None:
        if not self.enabled:
            return
        print(
            f"\nWordPress fingerprint scan\n"
            f"  Target:  {target}\n"
            f"  Profile: {profile}\n",
            file=self.stream,
            flush=True,
        )

    def phase(self, title: str) -> None:
        if not self.enabled:
            return
        print(f"==> {title}", file=self.stream, flush=True)

    def step(self, message: str) -> None:
        if not self.enabled:
            return
        self._step += 1
        print(f"  [{self._step}] {message}", file=self.stream, flush=True)

    def info(self, message: str) -> None:
        if not self.enabled:
            return
        print(f"      {message}", file=self.stream, flush=True)

    def done(self, message: str) -> None:
        if not self.enabled:
            return
        print(f"      done: {message}", file=self.stream, flush=True)

    @classmethod
    def null(cls) -> Progress:
        return cls(enabled=False)
