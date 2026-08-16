import pytest

from app.modules.base import Finding, MODULE_REGISTRY, ReconModule, register_module


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
