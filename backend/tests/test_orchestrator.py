from contextlib import ExitStack
from unittest.mock import patch

import pytest

from app.db import Base, engine, SessionLocal
from app import models, report_csv, report_data, report_pdf
from app.modules.base import Finding, MODULE_REGISTRY, ReconModule, register_module
from app.orchestrator import run_scan


@pytest.fixture(autouse=True)
def _all_tools_ok_by_default():
    # The real preflight_report() depends on what's actually installed
    # on the machine running the tests -- pin it to "everything ok" so
    # these tests stay deterministic and unrelated to this environment's
    # tool availability. test_run_scan_records_a_finding_for_missing_or_wrong_tools
    # overrides this to exercise the actual reporting behavior.
    with patch("app.orchestrator.preflight_report", return_value=[]):
        yield


def _mock_all_modules(overrides: dict | None = None, exclude: set | None = None) -> ExitStack:
    """Patches every registered module's .run to return [] by default, so
    tests stay deterministic and network-free as new modules get added --
    pass overrides={"module_name": [...]} to control specific ones, or
    exclude={"module_name"} to leave a module (e.g. a test-only fake) real."""
    overrides = overrides or {}
    exclude = exclude or set()
    stack = ExitStack()
    for name, cls in MODULE_REGISTRY.items():
        if name in exclude:
            continue
        stack.enter_context(patch.object(cls, "run", return_value=overrides.get(name, [])))
    return stack


def _create_authorized_project_and_scan():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Test Co",
            target="example.com",
            scope_notes="only example.com",
            authorized=True,
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def test_run_scan_persists_findings_and_marks_scan_complete():
    Base.metadata.create_all(bind=engine)
    scan_id = _create_authorized_project_and_scan()

    with _mock_all_modules(
        {
            "subfinder": [Finding("subdomain", "a.example.com")],
            "whois": [Finding("whois", "example.com")],
            "httpx_probe": [Finding("live_host", "https://a.example.com")],
        }
    ):
        run_scan(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert scan.status == "complete"
    assert scan.finished_at is not None
    # The test project has no explicit scope (defaults to {}), so the
    # discovered subdomain is out of scope and the orchestrator now
    # records that as an out_of_scope finding instead of dropping it silently.
    assert {f.type for f in findings} == {"subdomain", "whois", "live_host", "out_of_scope"}


def test_run_scan_records_a_finding_for_missing_or_wrong_tools():
    # Regression coverage for the real-world bug: on a machine missing
    # or shadowing external tools (e.g. subfinder not installed, httpx
    # on PATH resolving to the wrong same-named tool), the scan used to
    # only show this as a module_error buried in results -- easy to miss,
    # which is exactly what made the technology/CVE drop look mysterious
    # instead of explainable. It must now be a clear, upfront finding.
    scan_id = _create_authorized_project_and_scan()

    with _mock_all_modules():
        with patch(
            "app.orchestrator.preflight_report",
            return_value=[
                {
                    "name": "httpx",
                    "found": False,
                    "ok": False,
                    "detail": "found the wrong tool on PATH",
                },
                {"name": "nuclei", "found": True, "ok": True, "path": "/usr/bin/nuclei"},
            ],
        ):
            run_scan(scan_id)

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    tool_findings = [f for f in findings if f.type == "tool_missing"]
    assert len(tool_findings) == 1
    assert tool_findings[0].value == "httpx"
    assert tool_findings[0].data == {"detail": "found the wrong tool on PATH"}
    assert tool_findings[0].module == "orchestrator"


def _create_unauthorized_project_and_scan():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Unauthorized Co",
            target="unauth.com",
            scope_notes="not authorized",
            authorized=False,
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def test_run_scan_fails_without_running_modules_when_project_not_authorized():
    scan_id = _create_unauthorized_project_and_scan()

    with ExitStack() as stack:
        mocks = {
            name: stack.enter_context(patch.object(cls, "run", return_value=[]))
            for name, cls in MODULE_REGISTRY.items()
        }
        run_scan(scan_id)
        for mock in mocks.values():
            mock.assert_not_called()

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
    finally:
        db.close()

    assert scan.status == "failed"


def test_run_scan_isolates_a_failing_module_and_keeps_going():
    scan_id = _create_authorized_project_and_scan()

    with ExitStack() as stack:
        for name, cls in MODULE_REGISTRY.items():
            if name == "subfinder":
                stack.enter_context(patch.object(cls, "run", side_effect=RuntimeError("boom")))
            else:
                overrides = {
                    "crtsh": [Finding("subdomain", "a.example.com")],
                    "whois": [Finding("whois", "example.com")],
                    "httpx_probe": [Finding("live_host", "https://a.example.com")],
                }
                stack.enter_context(patch.object(cls, "run", return_value=overrides.get(name, [])))
        run_scan(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert scan.status == "complete"
    assert scan.finished_at is not None

    types_by_module = {(f.module, f.type) for f in findings}
    assert ("subfinder", "module_error") in types_by_module
    assert ("crtsh", "subdomain") in types_by_module
    assert ("whois", "whois") in types_by_module
    assert ("httpx_probe", "live_host") in types_by_module

    error_finding = next(f for f in findings if f.module == "subfinder")
    assert error_finding.value == "subfinder"
    assert "boom" in error_finding.data["error"]


def test_run_scan_threads_technologies_from_earlier_to_later_modules_by_run_order():
    seen_technologies = []

    class _EarlyTechModule(ReconModule):
        name = "_test_early_tech_module"
        run_order = 20

        def run(self, target, context):
            return [Finding(type="technology", value=target, data={"name": "nginx", "version": "1.18"})]

    class _LateCorrelationModule(ReconModule):
        name = "_test_late_correlation_module"
        run_order = 90

        def run(self, target, context):
            seen_technologies.append(list(context.get("technologies", [])))
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_EarlyTechModule)
        register_module(_LateCorrelationModule)

        with _mock_all_modules(exclude={_EarlyTechModule.name, _LateCorrelationModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_EarlyTechModule.name]
        del MODULE_REGISTRY[_LateCorrelationModule.name]

    assert seen_technologies == [[{"name": "nginx", "version": "1.18", "host": "example.com"}]]


def test_run_scan_calls_progress_callback_with_each_module_name_in_run_order():
    scan_id = _create_authorized_project_and_scan()
    seen_names = []

    with _mock_all_modules():
        run_scan(scan_id, progress_callback=seen_names.append)

    module_names_by_run_order = [
        name for name, _ in sorted(MODULE_REGISTRY.items(), key=lambda item: item[1].run_order)
    ]
    assert seen_names == module_names_by_run_order


def test_run_scan_threads_rate_limit_and_circuit_breaker_threshold_into_context():
    seen_context = {}

    class _ContextCapturingModule(ReconModule):
        name = "_test_context_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["rate_limit"] = context.get("rate_limit")
            seen_context["circuit_breaker_threshold"] = context.get("circuit_breaker_threshold")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_ContextCapturingModule)
        with _mock_all_modules(exclude={_ContextCapturingModule.name}):
            run_scan(scan_id, rate_limit=2.5, circuit_breaker_threshold=3)
    finally:
        del MODULE_REGISTRY[_ContextCapturingModule.name]

    assert seen_context == {"rate_limit": 2.5, "circuit_breaker_threshold": 3}


def test_run_scan_uses_default_rate_limit_and_threshold_when_not_specified():
    seen_context = {}

    class _DefaultContextCapturingModule(ReconModule):
        name = "_test_default_context_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["rate_limit"] = context.get("rate_limit")
            seen_context["circuit_breaker_threshold"] = context.get("circuit_breaker_threshold")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_DefaultContextCapturingModule)
        with _mock_all_modules(exclude={_DefaultContextCapturingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DefaultContextCapturingModule.name]

    assert seen_context == {"rate_limit": 5.0, "circuit_breaker_threshold": 5}


def test_run_scan_threads_max_workers_into_context():
    seen_context = {}

    class _MaxWorkersCapturingModule(ReconModule):
        name = "_test_max_workers_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["max_workers"] = context.get("max_workers")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_MaxWorkersCapturingModule)
        with _mock_all_modules(exclude={_MaxWorkersCapturingModule.name}):
            run_scan(scan_id, max_workers=7)
    finally:
        del MODULE_REGISTRY[_MaxWorkersCapturingModule.name]

    assert seen_context == {"max_workers": 7}


def test_run_scan_uses_default_max_workers_when_not_specified():
    seen_context = {}

    class _DefaultMaxWorkersCapturingModule(ReconModule):
        name = "_test_default_max_workers_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["max_workers"] = context.get("max_workers")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_DefaultMaxWorkersCapturingModule)
        with _mock_all_modules(exclude={_DefaultMaxWorkersCapturingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DefaultMaxWorkersCapturingModule.name]

    assert seen_context == {"max_workers": 1}


def test_run_scan_tracks_confirmed_subdomains_separately_from_permutation_guesses():
    # confirmed_subdomains feeds app.modules.base.prioritized_hosts, which
    # cloud_range/tech_fingerprint/browser_fingerprint use to try real
    # discoveries before subdomain_permutation's unconfirmed guesses --
    # this is the orchestrator half of that fix: only a non-permutation
    # module's subdomain Finding should land in confirmed_subdomains.
    class _RealDiscoveryModule(ReconModule):
        name = "_test_real_discovery_module"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value="real.example.com")]

    class _FakePermutationModule(ReconModule):
        name = "subdomain_permutation"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value="guessed.example.com")]

    class _LateContextCapturingModule(ReconModule):
        name = "_test_late_context_capturing_module_for_confirmed"
        run_order = 90

        def run(self, target, context):
            type(self).seen_subdomains = set(context.get("subdomains", set()))
            type(self).seen_confirmed = set(context.get("confirmed_subdomains", set()))
            return []

    db = SessionLocal()
    try:
        project = models.Project(
            name="Confirmed Subdomains Co",
            target="example.com",
            scope_notes="real and guessed both in scope",
            authorized=True,
            scope={"include": ["example.com", "real.example.com", "guessed.example.com"], "exclude": []},
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_RealDiscoveryModule)
        del MODULE_REGISTRY["subdomain_permutation"]
        register_module(_FakePermutationModule)
        register_module(_LateContextCapturingModule)
        with _mock_all_modules(
            exclude={
                _RealDiscoveryModule.name,
                _FakePermutationModule.name,
                _LateContextCapturingModule.name,
            }
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_RealDiscoveryModule.name]
        del MODULE_REGISTRY["subdomain_permutation"]
        del MODULE_REGISTRY[_LateContextCapturingModule.name]

    assert _LateContextCapturingModule.seen_subdomains == {
        "real.example.com", "guessed.example.com",
    }
    assert _LateContextCapturingModule.seen_confirmed == {"real.example.com"}


def test_run_scan_filters_out_of_scope_subdomains_before_later_modules_see_them():
    seen_subdomains = []

    class _DiscoveryModule(ReconModule):
        name = "_test_discovery_module"
        run_order = 10

        def run(self, target, context):
            return [
                Finding(type="subdomain", value="in-scope.example.com"),
                Finding(type="subdomain", value="out-of-scope.example.com"),
            ]

    class _LateContextCapturingModule(ReconModule):
        name = "_test_late_context_capturing_module"
        run_order = 90

        def run(self, target, context):
            seen_subdomains.append(set(context.get("subdomains", set())))
            return []

    db = SessionLocal()
    try:
        project = models.Project(
            name="Scope Filter Co",
            target="example.com",
            scope_notes="only in-scope.example.com",
            authorized=True,
            scope={
                "include": ["example.com", "in-scope.example.com"],
                "exclude": ["out-of-scope.example.com"],
            },
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_DiscoveryModule)
        register_module(_LateContextCapturingModule)
        with _mock_all_modules(
            exclude={_DiscoveryModule.name, _LateContextCapturingModule.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DiscoveryModule.name]
        del MODULE_REGISTRY[_LateContextCapturingModule.name]

    assert seen_subdomains == [{"in-scope.example.com"}]


def test_run_scan_caps_subdomain_candidates_and_records_one_finding_for_the_overflow():
    # A noisy passive source (subfinder's own crtsh source returned
    # 24,739 "subdomains" for example.com in live testing, mostly
    # one-off certificate-transparency noise, not real infrastructure)
    # must not flood the DB or every downstream active module.
    class _NoisyDiscoveryModule(ReconModule):
        name = "_test_noisy_discovery_module"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value=f"noisy{i}.example.com") for i in range(10)]

    class _LateContextCapturingModule(ReconModule):
        name = "_test_late_context_capturing_cap_module"
        run_order = 90

        def run(self, target, context):
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_NoisyDiscoveryModule)
        register_module(_LateContextCapturingModule)
        with _mock_all_modules(
            exclude={_NoisyDiscoveryModule.name, _LateContextCapturingModule.name}
        ):
            run_scan(scan_id, max_subdomains=3)
    finally:
        del MODULE_REGISTRY[_NoisyDiscoveryModule.name]
        del MODULE_REGISTRY[_LateContextCapturingModule.name]

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    subdomain_findings = [f for f in findings if f.type == "subdomain"]
    cap_findings = [f for f in findings if f.type == "subdomain_discovery_capped"]
    assert len(subdomain_findings) == 3
    assert len(cap_findings) == 1
    assert cap_findings[0].data["limit"] == 3


def test_run_scan_subdomain_cap_is_shared_across_discovery_modules_and_stops_downstream_processing():
    class _FirstDiscoveryModule(ReconModule):
        name = "_test_first_discovery_module"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value="a.example.com")]

    class _SecondDiscoveryModule(ReconModule):
        name = "_test_second_discovery_module"
        run_order = 11

        def run(self, target, context):
            return [Finding(type="subdomain", value="b.example.com")]

    class _ContextCapturingModule(ReconModule):
        name = "_test_context_capturing_module_for_cap"
        run_order = 90
        seen: set = set()

        def run(self, target, context):
            type(self).seen = set(context.get("subdomains", set()))
            return []

    db = SessionLocal()
    try:
        project = models.Project(
            name="Cap Scope Co",
            target="example.com",
            scope_notes="a and b both in scope",
            authorized=True,
            scope={"include": ["example.com", "a.example.com", "b.example.com"], "exclude": []},
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_FirstDiscoveryModule)
        register_module(_SecondDiscoveryModule)
        register_module(_ContextCapturingModule)
        with _mock_all_modules(
            exclude={
                _FirstDiscoveryModule.name,
                _SecondDiscoveryModule.name,
                _ContextCapturingModule.name,
            }
        ):
            run_scan(scan_id, max_subdomains=1)
    finally:
        del MODULE_REGISTRY[_FirstDiscoveryModule.name]
        del MODULE_REGISTRY[_SecondDiscoveryModule.name]
        del MODULE_REGISTRY[_ContextCapturingModule.name]

    # Only the first module's subdomain made it in before the (shared,
    # cross-module) cap of 1 was reached.
    assert _ContextCapturingModule.seen == {"a.example.com"}


def test_run_scan_skips_a_module_entirely_when_the_scope_window_is_closed():
    called = []

    class _WindowedModule(ReconModule):
        name = "_test_windowed_module"
        run_order = 20

        def run(self, target, context):
            called.append(self.name)
            return []

    db = SessionLocal()
    try:
        project = models.Project(
            name="Window Co",
            target="example.com",
            scope_notes="business hours only",
            authorized=True,
            scope={
                "include": ["example.com"],
                "allowed_window": {"start": "00:00", "end": "00:01"},
            },
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_WindowedModule)
        with _mock_all_modules(exclude={_WindowedModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_WindowedModule.name]

    assert called == []

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()
    window_closed = [f for f in findings if f.type == "scope_window_closed"]
    assert any(f.module == "_test_windowed_module" for f in window_closed)


def test_run_scan_always_threads_a_dict_scope_into_context_even_without_explicit_scope():
    seen_context = {}

    class _ScopeContextCapturingModule(ReconModule):
        name = "_test_scope_context_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["scope"] = context.get("scope")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_ScopeContextCapturingModule)
        with _mock_all_modules(exclude={_ScopeContextCapturingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_ScopeContextCapturingModule.name]

    assert seen_context["scope"] == {}
    assert isinstance(seen_context["scope"], dict)


def test_run_scan_works_without_a_progress_callback():
    scan_id = _create_authorized_project_and_scan()

    with _mock_all_modules():
        run_scan(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
    finally:
        db.close()
    assert scan.status == "complete"


def test_run_scan_persists_audit_entries_recorded_by_a_module():
    class _AuditingModule(ReconModule):
        name = "_test_auditing_module"
        run_order = 20

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="200", url="https://example.com/")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_AuditingModule)
        with _mock_all_modules(exclude={_AuditingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_AuditingModule.name]

    db = SessionLocal()
    try:
        entries = db.query(models.AuditEntry).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert len(entries) == 1
    assert entries[0].module == "_test_auditing_module"
    assert entries[0].target == "example.com"
    assert entries[0].outcome == "200"
    assert entries[0].url == "https://example.com/"


def test_run_scan_persists_audit_entries_from_each_module_separately_without_duplication():
    class _FirstAuditingModule(ReconModule):
        name = "_test_first_auditing_module"
        run_order = 20

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="200")
            return []

    class _SecondAuditingModule(ReconModule):
        name = "_test_second_auditing_module"
        run_order = 30

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="404")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_FirstAuditingModule)
        register_module(_SecondAuditingModule)
        with _mock_all_modules(
            exclude={_FirstAuditingModule.name, _SecondAuditingModule.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_FirstAuditingModule.name]
        del MODULE_REGISTRY[_SecondAuditingModule.name]

    db = SessionLocal()
    try:
        entries = db.query(models.AuditEntry).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert len(entries) == 2
    by_module = {e.module: e.outcome for e in entries}
    assert by_module == {
        "_test_first_auditing_module": "200",
        "_test_second_auditing_module": "404",
    }


def test_run_scan_keeps_audit_entries_recorded_before_a_module_crashes():
    class _CrashingAuditingModule(ReconModule):
        name = "_test_crashing_auditing_module"
        run_order = 20

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="error: connection reset")
            raise RuntimeError("boom")

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_CrashingAuditingModule)
        with _mock_all_modules(exclude={_CrashingAuditingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_CrashingAuditingModule.name]

    db = SessionLocal()
    try:
        entries = db.query(models.AuditEntry).filter_by(scan_id=scan_id).all()
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert len(entries) == 1
    assert entries[0].outcome == "error: connection reset"
    assert any(f.type == "module_error" and f.module == "_test_crashing_auditing_module" for f in findings)


def test_run_scan_records_out_of_scope_finding_for_discovery_filtered_subdomain():
    class _DiscoveryModule(ReconModule):
        name = "_test_discovery_module_for_audit"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value="blocked.example.com")]

    db = SessionLocal()
    try:
        project = models.Project(
            name="Discovery Scope Co",
            target="example.com",
            scope_notes="only example.com",
            authorized=True,
            scope={"include": ["example.com"], "exclude": ["blocked.example.com"]},
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_DiscoveryModule)
        with _mock_all_modules(exclude={_DiscoveryModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DiscoveryModule.name]

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    out_of_scope = [f for f in findings if f.type == "out_of_scope" and f.value == "blocked.example.com"]
    assert len(out_of_scope) == 1
    assert out_of_scope[0].module == "orchestrator"
    assert out_of_scope[0].data == {"module": "orchestrator"}


def test_run_scan_dedupes_out_of_scope_finding_when_two_modules_report_the_same_subdomain():
    class _FirstDiscoveryModule(ReconModule):
        name = "_test_first_discovery_module_for_dedup"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value="blocked.example.com")]

    class _SecondDiscoveryModule(ReconModule):
        name = "_test_second_discovery_module_for_dedup"
        run_order = 11

        def run(self, target, context):
            return [Finding(type="subdomain", value="blocked.example.com")]

    db = SessionLocal()
    try:
        project = models.Project(
            name="Discovery Scope Dedup Co",
            target="example.com",
            scope_notes="only example.com",
            authorized=True,
            scope={"include": ["example.com"], "exclude": ["blocked.example.com"]},
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_FirstDiscoveryModule)
        register_module(_SecondDiscoveryModule)
        with _mock_all_modules(
            exclude={_FirstDiscoveryModule.name, _SecondDiscoveryModule.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_FirstDiscoveryModule.name]
        del MODULE_REGISTRY[_SecondDiscoveryModule.name]

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    out_of_scope = [f for f in findings if f.type == "out_of_scope" and f.value == "blocked.example.com"]
    assert len(out_of_scope) == 1
    assert out_of_scope[0].module == "orchestrator"


def test_run_scan_includes_host_in_technologies_context():
    seen_technologies = []

    class _EarlyTechModuleHost(ReconModule):
        name = "_test_early_tech_module_host"
        run_order = 20

        def run(self, target, context):
            return [
                Finding(
                    type="technology",
                    value="tech.example.com",
                    data={"name": "nginx", "version": "1.18"},
                )
            ]

    class _LateCapturingModuleHost(ReconModule):
        name = "_test_late_capturing_module_host"
        run_order = 90

        def run(self, target, context):
            seen_technologies.append(list(context.get("technologies", [])))
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_EarlyTechModuleHost)
        register_module(_LateCapturingModuleHost)
        with _mock_all_modules(exclude={_EarlyTechModuleHost.name, _LateCapturingModuleHost.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_EarlyTechModuleHost.name]
        del MODULE_REGISTRY[_LateCapturingModuleHost.name]

    assert seen_technologies == [
        [{"name": "nginx", "version": "1.18", "host": "tech.example.com"}]
    ]


def test_run_scan_accumulates_cve_findings_for_later_modules():
    seen_cve_findings = []

    class _CveProducingModule(ReconModule):
        name = "_test_cve_producing_module"
        run_order = 90

        def run(self, target, context):
            return [
                Finding(
                    type="cve",
                    value="CVE-2021-23017",
                    data={"host": "tech.example.com", "status": "suspected"},
                )
            ]

    class _LateValidationCapturingModule(ReconModule):
        name = "_test_late_validation_capturing_module"
        run_order = 95

        def run(self, target, context):
            seen_cve_findings.append(list(context.get("cve_findings", [])))
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_CveProducingModule)
        register_module(_LateValidationCapturingModule)
        with _mock_all_modules(
            exclude={_CveProducingModule.name, _LateValidationCapturingModule.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_CveProducingModule.name]
        del MODULE_REGISTRY[_LateValidationCapturingModule.name]

    assert seen_cve_findings == [[{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]]


def test_run_scan_merges_cve_validation_finding_into_the_matching_cve_finding():
    class _CveProducingModuleForMerge(ReconModule):
        name = "_test_cve_producing_module_for_merge"
        run_order = 90

        def run(self, target, context):
            return [
                Finding(
                    type="cve",
                    value="CVE-2021-23017",
                    data={"host": "tech.example.com", "status": "suspected"},
                )
            ]

    class _ValidationModuleForMerge(ReconModule):
        name = "_test_validation_module_for_merge"
        run_order = 95

        def run(self, target, context):
            return [
                Finding(
                    type="cve_validation",
                    value="CVE-2021-23017",
                    data={
                        "host": "tech.example.com",
                        "status": "confirmed",
                        "nuclei_template_id": "CVE-2021-23017",
                    },
                )
            ]

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_CveProducingModuleForMerge)
        register_module(_ValidationModuleForMerge)
        with _mock_all_modules(
            exclude={_CveProducingModuleForMerge.name, _ValidationModuleForMerge.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_CveProducingModuleForMerge.name]
        del MODULE_REGISTRY[_ValidationModuleForMerge.name]

    db = SessionLocal()
    try:
        cve_rows = db.query(models.Finding).filter_by(scan_id=scan_id, type="cve").all()
        validation_rows = db.query(models.Finding).filter_by(scan_id=scan_id, type="cve_validation").all()
    finally:
        db.close()

    assert len(cve_rows) == 1
    assert cve_rows[0].data["status"] == "confirmed"
    assert cve_rows[0].data["nuclei_template_id"] == "CVE-2021-23017"
    assert validation_rows == []


def test_run_scan_accumulates_validated_by_when_two_tools_confirm_the_same_cve():
    """nuclei_validation and msf_validation are independent active
    confirmation engines that can both run against the same CVE -- the
    second validator's merge must not erase the first tool's evidence,
    and both tool names must survive in validated_by."""

    class _CveProducingModuleForMultiTool(ReconModule):
        name = "_test_cve_producing_module_for_multi_tool"
        run_order = 90

        def run(self, target, context):
            return [
                Finding(
                    type="cve",
                    value="CVE-2021-23017",
                    data={"host": "tech.example.com", "status": "suspected"},
                )
            ]

    class _NucleiLikeValidationModule(ReconModule):
        name = "_test_nuclei_like_validation_module"
        run_order = 95

        def run(self, target, context):
            return [
                Finding(
                    type="cve_validation",
                    value="CVE-2021-23017",
                    data={
                        "host": "tech.example.com",
                        "status": "confirmed",
                        "tool": "nuclei",
                        "nuclei_template_id": "CVE-2021-23017",
                        "confirmation_note_en": "Confirmed via nuclei.",
                    },
                )
            ]

    class _MsfLikeValidationModule(ReconModule):
        name = "_test_msf_like_validation_module"
        run_order = 96

        def run(self, target, context):
            return [
                Finding(
                    type="cve_validation",
                    value="CVE-2021-23017",
                    data={
                        "host": "tech.example.com",
                        "status": "confirmed",
                        "tool": "metasploit",
                        "msf_module": "exploit/multi/http/example",
                        "msf_confirmation_note_en": "Confirmed via Metasploit.",
                    },
                )
            ]

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_CveProducingModuleForMultiTool)
        register_module(_NucleiLikeValidationModule)
        register_module(_MsfLikeValidationModule)
        with _mock_all_modules(
            exclude={
                _CveProducingModuleForMultiTool.name,
                _NucleiLikeValidationModule.name,
                _MsfLikeValidationModule.name,
            }
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_CveProducingModuleForMultiTool.name]
        del MODULE_REGISTRY[_NucleiLikeValidationModule.name]
        del MODULE_REGISTRY[_MsfLikeValidationModule.name]

    db = SessionLocal()
    try:
        cve_rows = db.query(models.Finding).filter_by(scan_id=scan_id, type="cve").all()
    finally:
        db.close()

    assert len(cve_rows) == 1
    data = cve_rows[0].data
    assert data["status"] == "confirmed"
    assert set(data["validated_by"]) == {"nuclei", "metasploit"}
    # Both tools' own evidence keys survive the second tool's merge.
    assert data["nuclei_template_id"] == "CVE-2021-23017"
    assert data["confirmation_note_en"] == "Confirmed via nuclei."
    assert data["msf_module"] == "exploit/multi/http/example"
    assert data["msf_confirmation_note_en"] == "Confirmed via Metasploit."


def test_epss_score_and_remediation_survive_into_report_data_and_all_renderers(tmp_path):
    """Exercises the full real pipeline: a cve Finding carrying an epss_score
    (what cve_correlation + fetch_epss would produce) gets merged, via the
    orchestrator's real _apply_cve_validation, with a cve_validation Finding
    carrying a remediation_en (what nuclei_validation would produce for a
    confirmed CVE) -- and both values must survive into build_report_data()
    and flow into the CSV and PDF renderers, none of which is covered by any
    single existing task's tests."""

    class _CveProducingModuleForPipeline(ReconModule):
        name = "_test_cve_producing_module_for_pipeline"
        run_order = 90

        def run(self, target, context):
            return [
                Finding(
                    type="cve",
                    value="CVE-2021-44228",
                    data={
                        "host": "tech.example.com",
                        "status": "suspected",
                        "severity": "CRITICAL",
                        "cvss_score": 10.0,
                        "epss_score": 0.975,
                        "matched_technology": "log4j",
                        "matched_technology_version": "2.14.1",
                        "description_en": "Remote code execution in log4j.",
                        "confirmation_note_en": "-",
                    },
                )
            ]

    class _ValidationModuleForPipeline(ReconModule):
        name = "_test_validation_module_for_pipeline"
        run_order = 95

        def run(self, target, context):
            return [
                Finding(
                    type="cve_validation",
                    value="CVE-2021-44228",
                    data={
                        "host": "tech.example.com",
                        "status": "confirmed",
                        "nuclei_template_id": "CVE-2021-44228",
                        "remediation_en": "Upgrade log4j to 2.17.1 or later.",
                        "confirmation_note_en": "Confirmed via nuclei template CVE-2021-44228.",
                    },
                )
            ]

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_CveProducingModuleForPipeline)
        register_module(_ValidationModuleForPipeline)
        with _mock_all_modules(
            exclude={_CveProducingModuleForPipeline.name, _ValidationModuleForPipeline.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_CveProducingModuleForPipeline.name]
        del MODULE_REGISTRY[_ValidationModuleForPipeline.name]

    data = report_data.build_report_data(scan_id, "en")

    assert data is not None
    assert len(data.cves) == 1
    row = data.cves[0]
    assert row.cve_id == "CVE-2021-44228"
    assert row.status == "confirmed"
    assert row.epss_score == 0.975
    assert row.remediation == "Upgrade log4j to 2.17.1 or later."

    csv_text = report_csv.render_csv(data, "en")
    assert "CVE-2021-44228" in csv_text

    pdf_path = str(tmp_path / "pipeline_report.pdf")
    report_pdf.render_pdf(data, pdf_path, "en")
    from pypdf import PdfReader

    reader = PdfReader(pdf_path)
    pdf_text = "\n".join(page.extract_text() for page in reader.pages)
    assert "CVE-2021-44228" in pdf_text.replace("\n", "")
