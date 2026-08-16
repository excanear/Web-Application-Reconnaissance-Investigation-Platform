import subprocess

from app.modules.base import Finding, ReconModule, register_module


@register_module
class SubfinderModule(ReconModule):
    name = "subfinder"
    discovers_subdomains = True

    def run(self, target: str, context: dict) -> list[Finding]:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent"],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        subdomains = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        return [Finding(type="subdomain", value=s) for s in sorted(subdomains)]
