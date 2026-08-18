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
        audit = context.get("audit")
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
        try:
            result = subprocess.run(
                command,
                input="\n".join(sorted(hosts)),
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            if audit is not None:
                for host in hosts:
                    audit.record(module=self.name, target=host, outcome=f"error: {exc}")
            raise

        # httpx makes its own requests internally -- we can't see the
        # individual ones it made, only correlate its output back to the
        # hosts we sent it. A host missing from the output gets no_response.
        seen_hosts = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            host_target = record.get("input") or record.get("url", "")
            seen_hosts.add(host_target)
            if audit is not None:
                status = record.get("status_code")
                audit.record(
                    module=self.name,
                    target=host_target,
                    outcome=str(status) if status is not None else "no_response",
                    url=record.get("url"),
                )
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

        if audit is not None:
            for host in hosts - seen_hosts:
                audit.record(module=self.name, target=host, outcome="no_response")

        return findings
