import requests

from app.modules.base import Finding, ReconModule


class CrtShModule(ReconModule):
    name = "crtsh"

    def run(self, target: str, context: dict) -> list[Finding]:
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
