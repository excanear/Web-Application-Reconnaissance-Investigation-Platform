# Importing these submodules triggers their @register_module decorator,
# populating app.modules.base.MODULE_REGISTRY. Import order controls
# registry iteration order (dict preserves insertion order).
from app.modules import crtsh, subfinder, permutation, httpx_probe, whois_module  # noqa: F401
