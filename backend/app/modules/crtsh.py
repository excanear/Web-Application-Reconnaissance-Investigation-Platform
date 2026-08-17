import requests

from app.modules.base import Finding, ReconModule, register_module
from app.scope import is_in_scope


@register_module
class CrtShModule(ReconModule):
    name = "crtsh"
    run_order = 10

    def run(self, target: str, context: dict) -> list[Finding]:
        scope = context.get("scope")
        if scope is not None and not is_in_scope(target, None, scope):
            return [Finding(type="out_of_scope", value=target, data={"module": self.name})]

        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=30,
        )
        response.raise_for_status()

        subdomains = set()
        for entry in response.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().removeprefix("*.")
                if name == target or name.endswith("." + target):
                    subdomains.add(name)

        return [
            Finding(type="subdomain", value=s, data={"source": "crt.sh"})
            for s in sorted(subdomains)
        ]
