# Importing these submodules triggers their @register_module decorator,
# populating app.modules.base.MODULE_REGISTRY. Import order controls
# registry iteration order (dict preserves insertion order).
from app.modules import (  # noqa: F401
    cloud_range,
    crtsh,
    subfinder,
    permutation,
    httpx_probe,
    whois_module,
)
