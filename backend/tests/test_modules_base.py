import pytest

from app.modules.base import Finding, MODULE_REGISTRY, ReconModule, prioritized_hosts, register_module


def test_finding_defaults_to_empty_data_dict():
    finding = Finding(type="subdomain", value="a.example.com")
    assert finding.data == {}


def test_recon_module_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ReconModule()


def test_recon_module_defaults_run_order_to_fifty():
    class _DefaultOrderModule(ReconModule):
        name = "_default_order_test_module"

        def run(self, target: str, context: dict) -> list[Finding]:
            return []

    try:
        register_module(_DefaultOrderModule)
        assert _DefaultOrderModule.run_order == 50
    finally:
        del MODULE_REGISTRY[_DefaultOrderModule.name]


def test_recon_module_defaults_is_active_to_false():
    class _PassiveModule(ReconModule):
        name = "_passive_test_module"

        def run(self, target: str, context: dict) -> list[Finding]:
            return []

    try:
        register_module(_PassiveModule)
        assert _PassiveModule.is_active is False
    finally:
        del MODULE_REGISTRY[_PassiveModule.name]


def test_register_module_adds_class_to_registry_by_name():
    class _FakeModule(ReconModule):
        name = "_fake_test_module"
        run_order = 10

        def run(self, target: str, context: dict) -> list[Finding]:
            return []

    try:
        register_module(_FakeModule)
        assert MODULE_REGISTRY["_fake_test_module"] is _FakeModule
    finally:
        del MODULE_REGISTRY[_FakeModule.name]


# --- prioritized_hosts ------------------------------------------------


def test_prioritized_hosts_puts_confirmed_subdomains_before_permutation_only_guesses():
    # The real-world bug this fixes: subdomain_permutation guesses like
    # "admin-amy.artssystem.com.br" sort alphabetically *before* the real
    # "amy.artssystem.com.br" it was guessed from, because "-" < "." in
    # ASCII -- a plain alphabetical sort put every dead guess ahead of
    # confirmed live hosts, and a module's circuit breaker exhausted on
    # the guesses before ever reaching a host httpx_probe had already
    # confirmed live.
    context = {
        "subdomains": {
            "amy.example.com", "admin-amy.example.com", "admin-zzz.example.com",
        },
        "confirmed_subdomains": {"amy.example.com"},
    }

    hosts = prioritized_hosts(context, "example.com")

    confirmed_count = 2  # target + amy.example.com
    assert hosts[:confirmed_count] == ["amy.example.com", "example.com"]
    assert hosts[confirmed_count:] == ["admin-amy.example.com", "admin-zzz.example.com"]


def test_prioritized_hosts_always_puts_the_target_first_even_when_it_sorts_later():
    context = {"subdomains": {"a.example.com"}, "confirmed_subdomains": {"a.example.com"}}

    hosts = prioritized_hosts(context, "zzz.example.com")

    assert hosts == ["a.example.com", "zzz.example.com"]


def test_prioritized_hosts_falls_back_to_a_plain_sort_when_nothing_is_confirmed():
    # Every unit test that builds a raw context dict without going
    # through the orchestrator (i.e. without a confirmed_subdomains key)
    # must keep working exactly as before this fix.
    context = {"subdomains": {"host0.example.com", "host1.example.com"}}

    hosts = prioritized_hosts(context, "example.com")

    assert hosts == ["example.com", "host0.example.com", "host1.example.com"]


def test_prioritized_hosts_a_host_confirmed_by_a_real_module_stays_confirmed_even_if_permutation_also_guessed_it():
    context = {
        "subdomains": {"api.example.com"},
        "confirmed_subdomains": {"api.example.com"},
    }

    hosts = prioritized_hosts(context, "example.com")

    assert hosts == ["api.example.com", "example.com"]
