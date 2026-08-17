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
