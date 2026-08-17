from unittest.mock import patch

from app.modules.cloud_range import CloudRangeModule


def test_cloud_range_flags_host_resolving_into_a_known_aws_range():
    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"
    ):
        findings = CloudRangeModule().run("example.com", {"subdomains": {"a.example.com"}})

    by_value = {f.value: f for f in findings}
    finding = by_value["a.example.com"]
    assert finding.type == "cloud_asset"
    assert finding.data["ip"] == "3.5.140.1"
    assert finding.data["provider"] == "aws"


def test_cloud_range_ignores_hosts_that_resolve_outside_known_ranges():
    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="8.8.8.8"
    ):
        findings = CloudRangeModule().run("example.com", {"subdomains": {"a.example.com"}})

    assert findings == []


def test_cloud_range_skips_hosts_that_fail_to_resolve():
    with patch(
        "app.modules.cloud_range.socket.gethostbyname", side_effect=OSError("no dns")
    ):
        findings = CloudRangeModule().run("example.com", {"subdomains": {"a.example.com"}})

    assert findings == []


def test_cloud_range_checks_target_itself_alongside_discovered_subdomains():
    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"
    ):
        findings = CloudRangeModule().run("example.com", {})

    assert [f.value for f in findings] == ["example.com"]


def test_circuit_breaker_trips_after_threshold_consecutive_resolution_failures():
    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.cloud_range.socket.gethostbyname", side_effect=OSError("no dns")
    ):
        findings = CloudRangeModule().run(
            "example.com", {"subdomains": subdomains, "circuit_breaker_threshold": 2}
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "cloud_range"
    assert tripped[0].data["skipped_hosts"] == 4


def test_rate_limiter_paces_requests_between_hosts():
    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="8.8.8.8"
    ), patch("app.modules.cloud_range.RateLimiter.wait") as mock_wait:
        CloudRangeModule().run(
            "example.com", {"subdomains": {"a.example.com"}, "rate_limit": 10.0}
        )

    assert mock_wait.call_count == 2


def test_out_of_scope_hosts_are_skipped_after_resolution():
    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"
    ):
        findings = CloudRangeModule().run(
            "example.com", {"subdomains": {"blocked.example.com"}, "scope": scope}
        )

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "cloud_range"}
    cloud_assets = [f for f in findings if f.type == "cloud_asset"]
    assert [f.value for f in cloud_assets] == ["example.com"]


def test_cidr_scope_entry_matches_resolved_ip():
    scope = {"include": ["3.5.128.0/18"]}

    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"
    ):
        findings = CloudRangeModule().run("example.com", {"scope": scope})

    cloud_assets = [f for f in findings if f.type == "cloud_asset"]
    assert [f.value for f in cloud_assets] == ["example.com"]
    assert not any(f.type == "out_of_scope" for f in findings)
