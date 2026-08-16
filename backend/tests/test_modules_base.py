import pytest

from app.modules.base import Finding, MODULE_REGISTRY, ReconModule, register_module


def test_finding_defaults_to_empty_data_dict():
    finding = Finding(type="subdomain", value="a.example.com")
    assert finding.data == {}


def test_recon_module_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ReconModule()


def test_recon_module_defaults_discovers_subdomains_to_false():
    class _NonDiscoveryModule(ReconModule):
        name = "_non_discovery_test_module"

        def run(self, target: str, context: dict) -> list[Finding]:
            return []

    try:
        register_module(_NonDiscoveryModule)
        assert _NonDiscoveryModule.discovers_subdomains is False
    finally:
        del MODULE_REGISTRY[_NonDiscoveryModule.name]


def test_register_module_adds_class_to_registry_by_name():
    class _FakeModule(ReconModule):
        name = "_fake_test_module"
        discovers_subdomains = True

        def run(self, target: str, context: dict) -> list[Finding]:
            return []

    try:
        register_module(_FakeModule)
        assert MODULE_REGISTRY["_fake_test_module"] is _FakeModule
    finally:
        del MODULE_REGISTRY[_FakeModule.name]
