from unittest.mock import patch

import pytest

from app.ratelimit import CircuitBreaker, RateLimiter


def test_rate_limiter_does_not_sleep_on_first_call():
    limiter = RateLimiter(5.0)

    with patch("app.ratelimit.time.sleep") as mock_sleep, patch(
        "app.ratelimit.time.monotonic", return_value=100.0
    ):
        limiter.wait()

    mock_sleep.assert_not_called()


def test_rate_limiter_sleeps_to_respect_pace_between_calls():
    limiter = RateLimiter(5.0)  # min interval: 0.2s
    times = iter([100.0, 100.05])

    with patch("app.ratelimit.time.sleep") as mock_sleep, patch(
        "app.ratelimit.time.monotonic", side_effect=lambda: next(times)
    ):
        limiter.wait()
        limiter.wait()

    mock_sleep.assert_called_once()
    (slept,), _ = mock_sleep.call_args
    assert slept == pytest.approx(0.15)


def test_rate_limiter_does_not_sleep_when_enough_time_already_passed():
    limiter = RateLimiter(5.0)
    times = iter([100.0, 101.0])

    with patch("app.ratelimit.time.sleep") as mock_sleep, patch(
        "app.ratelimit.time.monotonic", side_effect=lambda: next(times)
    ):
        limiter.wait()
        limiter.wait()

    mock_sleep.assert_not_called()


def test_circuit_breaker_stays_closed_below_threshold():
    breaker = CircuitBreaker(threshold=3)

    assert breaker.record_failure() is False
    assert breaker.record_failure() is False
    assert breaker.is_open is False


def test_circuit_breaker_trips_at_threshold():
    breaker = CircuitBreaker(threshold=3)
    breaker.record_failure()
    breaker.record_failure()

    assert breaker.record_failure() is True
    assert breaker.is_open is True


def test_circuit_breaker_resets_on_success():
    breaker = CircuitBreaker(threshold=3)
    breaker.record_failure()
    breaker.record_failure()

    breaker.record_success()

    assert breaker.record_failure() is False
    assert breaker.is_open is False


import threading
from concurrent.futures import ThreadPoolExecutor


def test_rate_limiter_serializes_concurrent_waits_to_respect_the_pace():
    # 20 req/s -> min interval 0.05s. 5 threads all call wait() at once;
    # since the limiter must serialize them to respect the global pace,
    # completing all 5 takes at least 4 intervals (the first call never
    # waits, each of the other 4 waits ~0.05s behind the previous one).
    limiter = RateLimiter(20.0)
    start = None

    def call():
        nonlocal start
        limiter.wait()

    threads = [threading.Thread(target=call) for _ in range(5)]
    import time

    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0

    assert elapsed >= 0.05 * 4 * 0.8  # 20% slack for scheduling jitter


def test_circuit_breaker_loses_no_increments_under_concurrent_failures():
    # threshold high enough that it never trips -- this test is purely
    # about the internal counter surviving concurrent increments without
    # a lost update, not about trip behavior.
    breaker = CircuitBreaker(threshold=1000)

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(lambda _: breaker.record_failure(), range(200)))

    assert breaker._consecutive_failures == 200
    assert breaker.is_open is False


def test_circuit_breaker_trips_exactly_once_the_threshold_is_reached_concurrently():
    breaker = CircuitBreaker(threshold=50)

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(lambda _: breaker.record_failure(), range(50)))

    assert breaker._consecutive_failures == 50
    assert breaker.is_open is True
