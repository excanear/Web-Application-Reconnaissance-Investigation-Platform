from app.modules.base import Finding, MODULE_REGISTRY, register_module
from app.modules.cve_validator_base import ActiveCveValidatorModule


class _FakeValidator(ActiveCveValidatorModule):
    name = "_test_fake_validator"

    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def _validate(self, cve_id, host, context):
        self.calls.append((cve_id, host))
        return self.results.get(cve_id, (None, True))


def test_confirms_when_validate_returns_a_finding():
    finding = Finding(type="cve_validation", value="CVE-2021-1", data={"status": "confirmed"})
    validator = _FakeValidator(results={"CVE-2021-1": (finding, True)})
    context = {"cve_findings": [{"cve_id": "CVE-2021-1", "host": "a.example.com"}]}

    findings = validator.run("example.com", context)

    assert findings == [finding]


def test_skips_entries_missing_cve_id_or_host():
    validator = _FakeValidator()
    context = {
        "cve_findings": [
            {"cve_id": None, "host": "a.example.com"},
            {"cve_id": "CVE-2021-1", "host": None},
            {},
        ]
    }

    findings = validator.run("example.com", context)

    assert findings == []
    assert validator.calls == []


def test_skips_out_of_scope_hosts_without_calling_validate():
    validator = _FakeValidator()
    context = {
        "cve_findings": [{"cve_id": "CVE-2021-1", "host": "blocked.example.com"}],
        "scope": {"include": ["example.com"], "exclude": ["blocked.example.com"]},
    }

    findings = validator.run("example.com", context)

    assert validator.calls == []
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "blocked.example.com"


def test_a_benign_no_match_does_not_count_against_the_circuit_breaker():
    # The exact class of bug fixed twice already in this project
    # (nuclei_validation, msf_validation): "ran fine, nothing to
    # confirm" is (None, True) and must never trip the breaker.
    validator = _FakeValidator(
        results={f"CVE-2021-{i}": (None, True) for i in range(10)}
    )
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-2021-{i}", "host": "a.example.com"} for i in range(10)
        ],
        "circuit_breaker_threshold": 2,
    }

    findings = validator.run("example.com", context)

    assert findings == []
    assert len(validator.calls) == 10  # every single one attempted, none skipped


def test_circuit_breaker_trips_on_genuine_consecutive_failures():
    validator = _FakeValidator(
        results={f"CVE-2021-{i}": (None, False) for i in range(5)}
    )
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-2021-{i}", "host": "a.example.com"} for i in range(5)
        ],
        "circuit_breaker_threshold": 2,
    }

    findings = validator.run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "_test_fake_validator"
    assert tripped[0].data["skipped_checks"] == 3
    assert len(validator.calls) == 2  # stopped right after the breaker tripped


def test_subclasses_share_the_registry_independently():
    @register_module
    class _AnotherFakeValidator(ActiveCveValidatorModule):
        name = "_test_another_fake_validator"

        def _validate(self, cve_id, host, context):
            return None, True

    try:
        assert MODULE_REGISTRY["_test_another_fake_validator"] is _AnotherFakeValidator
        assert _AnotherFakeValidator.run_order == 95
        assert _AnotherFakeValidator.is_active is True
    finally:
        del MODULE_REGISTRY["_test_another_fake_validator"]
