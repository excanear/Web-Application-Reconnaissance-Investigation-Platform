"""Pure scope-matching logic. Every module that touches a host calls
is_in_scope() before making a request; the orchestrator also calls it to
filter newly discovered subdomains before they reach later modules."""

import ipaddress
from datetime import datetime, time


def _parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _domain_matches(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host != suffix and host.endswith("." + suffix)
    return host == pattern or host.endswith("." + pattern)


def _matches_entry(host: str, ip: str | None, entry: str) -> bool:
    network = _parse_network(entry)
    if network is not None:
        if ip is None:
            return False
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False
    return _domain_matches(host, entry)


def is_in_scope(host: str, ip: str | None, scope: dict) -> bool:
    exclude = scope.get("exclude", [])
    if any(_matches_entry(host, ip, entry) for entry in exclude):
        return False
    include = scope.get("include", [])
    return any(_matches_entry(host, ip, entry) for entry in include)


def _parse_hhmm(value: str) -> time:
    hour, minute = value.split(":")
    return time(int(hour), int(minute))


def is_within_window(scope: dict, now: datetime | None = None) -> bool:
    window = scope.get("allowed_window")
    if not window:
        return True
    now = now or datetime.utcnow()
    start = _parse_hhmm(window["start"])
    end = _parse_hhmm(window["end"])
    current = now.time()
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end
