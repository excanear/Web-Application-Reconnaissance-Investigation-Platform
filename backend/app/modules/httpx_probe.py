import json
import subprocess

from app.modules.base import Finding, ReconModule, register_module


@register_module
class HttpxProbeModule(ReconModule):
    name = "httpx_probe"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = context.get("subdomains", set()) | {target}
        result = subprocess.run(
            ["httpx", "-silent", "-json", "-tech-detect"],
            input="\n".join(sorted(hosts)),
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            findings.append(
                Finding(
                    type="live_host",
                    value=record.get("url", record.get("input", "")),
                    data={
                        "status_code": record.get("status_code"),
                        "technologies": record.get("tech", []),
                        "title": record.get("title"),
                    },
                )
            )
        return findings
