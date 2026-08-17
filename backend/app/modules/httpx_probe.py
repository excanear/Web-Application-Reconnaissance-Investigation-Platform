import json
import subprocess

from app.modules.base import Finding, ReconModule, register_module
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0


@register_module
class HttpxProbeModule(ReconModule):
    name = "httpx_probe"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = context.get("subdomains", set()) | {target}
        scope = context.get("scope")
        findings: list[Finding] = []

        if scope is not None:
            in_scope_hosts = set()
            for host in hosts:
                if is_in_scope(host, None, scope):
                    in_scope_hosts.add(host)
                else:
                    findings.append(
                        Finding(type="out_of_scope", value=host, data={"module": self.name})
                    )
            hosts = in_scope_hosts

        rate_limit = context.get("rate_limit", DEFAULT_RATE_LIMIT)
        # httpx paces its own requests natively -- pass our limit through
        # instead of reimplementing pacing for a subprocess we don't
        # control the request loop of.
        command = [
            "httpx",
            "-silent",
            "-json",
            "-tech-detect",
            "-rate-limit",
            str(max(1, round(rate_limit))),
        ]
        result = subprocess.run(
            command,
            input="\n".join(sorted(hosts)),
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )

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
