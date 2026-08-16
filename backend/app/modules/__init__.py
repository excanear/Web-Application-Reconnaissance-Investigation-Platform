# Importing these submodules triggers their @register_module decorator,
# populating app.modules.base.MODULE_REGISTRY. Import order controls
# registry iteration order (dict preserves insertion order).
from app.modules import crtsh, httpx_probe, subfinder, whois_module  # noqa: F401
