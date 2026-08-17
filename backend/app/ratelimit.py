"""Shared pacing and failure-isolation primitives for modules that make
real network requests against a target. Each module owns its own
RateLimiter/CircuitBreaker instance per run - state never persists across
scans."""

import time


class RateLimiter:
    """Paces calls to at most `requests_per_second`, sleeping just enough
    since the previous call to respect that rate. The first call never
    sleeps - there's nothing to pace against yet."""

    def __init__(self, requests_per_second: float):
        self._min_interval = 1.0 / requests_per_second
        self._last_call: float | None = None

    def wait(self) -> None:
        now = time.monotonic()
        if self._last_call is not None:
            elapsed = now - self._last_call
            remaining = self._min_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
                now = self._last_call + self._min_interval
        self._last_call = now


class CircuitBreaker:
    """Tracks consecutive failures; trips (opens) once `threshold` failures
    happen in a row without an intervening success. A single success
    resets the streak."""

    def __init__(self, threshold: int):
        self._threshold = threshold
        self._consecutive_failures = 0
        self.is_open = False

    def record_success(self) -> None:
        self._consecutive_failures = 0

    def record_failure(self) -> bool:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._threshold:
            self.is_open = True
        return self.is_open
