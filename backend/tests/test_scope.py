from datetime import datetime

from app.scope import is_in_scope, is_within_window


def test_bare_domain_pattern_matches_apex_and_subdomains():
    scope = {"include": ["example.com"]}
    assert is_in_scope("example.com", None, scope) is True
    assert is_in_scope("a.example.com", None, scope) is True
    assert is_in_scope("a.b.example.com", None, scope) is True


def test_bare_domain_pattern_does_not_match_unrelated_domain():
    scope = {"include": ["example.com"]}
    assert is_in_scope("example.com.evil.com", None, scope) is False
    assert is_in_scope("notexample.com", None, scope) is False


def test_wildcard_pattern_matches_only_subdomains_not_apex():
    scope = {"include": ["*.example.com"]}
    assert is_in_scope("a.example.com", None, scope) is True
    assert is_in_scope("example.com", None, scope) is False


def test_cidr_entry_matches_ip_within_range():
    scope = {"include": ["10.0.0.0/8"]}
    assert is_in_scope("anything.example.com", "10.1.2.3", scope) is True


def test_cidr_entry_does_not_match_ip_outside_range():
    scope = {"include": ["10.0.0.0/8"]}
    assert is_in_scope("anything.example.com", "8.8.8.8", scope) is False


def test_cidr_entry_never_matches_when_ip_not_provided():
    scope = {"include": ["10.0.0.0/8"]}
    assert is_in_scope("anything.example.com", None, scope) is False


def test_exclude_wins_over_include():
    scope = {"include": ["example.com"], "exclude": ["internal.example.com"]}
    assert is_in_scope("internal.example.com", None, scope) is False
    assert is_in_scope("api.example.com", None, scope) is True


def test_empty_include_fails_closed():
    assert is_in_scope("example.com", None, {}) is False
    assert is_in_scope("example.com", None, {"include": []}) is False


def test_is_within_window_returns_true_when_no_window_configured():
    assert is_within_window({}) is True


def test_is_within_window_returns_true_inside_window():
    scope = {"allowed_window": {"start": "09:00", "end": "18:00"}}
    now = datetime(2026, 8, 17, 12, 0)
    assert is_within_window(scope, now=now) is True


def test_is_within_window_returns_false_outside_window():
    scope = {"allowed_window": {"start": "09:00", "end": "18:00"}}
    now = datetime(2026, 8, 17, 20, 0)
    assert is_within_window(scope, now=now) is False


def test_is_within_window_handles_window_crossing_midnight():
    scope = {"allowed_window": {"start": "22:00", "end": "06:00"}}
    late_night = datetime(2026, 8, 17, 23, 0)
    early_morning = datetime(2026, 8, 17, 3, 0)
    midday = datetime(2026, 8, 17, 12, 0)
    assert is_within_window(scope, now=late_night) is True
    assert is_within_window(scope, now=early_morning) is True
    assert is_within_window(scope, now=midday) is False
