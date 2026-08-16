import pytest

from app.modules.base import Finding, ReconModule


def test_finding_defaults_to_empty_data_dict():
    finding = Finding(type="subdomain", value="a.example.com")
    assert finding.data == {}


def test_recon_module_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ReconModule()
