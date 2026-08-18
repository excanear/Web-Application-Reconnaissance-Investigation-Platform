import json
import subprocess
from urllib.parse import urlparse

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
        except OSError as exc:
            # httpx never even launched (e.g. the binary isn't installed) --
            # distinguish "never attempted" from "attempted and failed" so the
            # audit trail doesn't imply a request was made when none was.
            if audit is not None:
                for host in sorted(hosts):
                    audit.record(module=self.name, target=host, outcome=f"not_attempted: {exc}")
            raise
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            if audit is not None:
                for host in sorted(hosts):
                    audit.record(module=self.name, target=host, outcome=f"error: {exc}")
            raise

        # httpx makes its own requests internally -- we can't see the
        # individual ones it made, only correlate its output back to the
        # hosts we sent it. A host missing from the output gets no_response.
        # Build a lookup keyed by every identifying value a parsed record
        # could match (both "input" and "url") so a record with only one of
        # the two fields still correlates correctly back to the bare
        # hostname form used in `hosts` -- a record keyed only by URL form
        # must never be mistaken for "this host never responded".
        parsed_by_key: dict[str, dict] = {}
        parsed_records = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            parsed_records.append(record)
            keys = [record.get("input"), record.get("url")]
            url = record.get("url")
            if url:
                # A record with only "url" (no "input") still needs to
                # correlate back to the bare hostname form used in `hosts` --
                # otherwise the bare host looks unseen even though this
                # record is its real response, producing a false
                # "no_response" alongside the real outcome.
                hostname = urlparse(url).hostname
                if hostname:
                    keys.append(hostname)
            for key in keys:
                if key:
                    parsed_by_key[key] = record
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
            for host in sorted(hosts):
                record = parsed_by_key.get(host)
                status = record.get("status_code") if record else None
                audit.record(
                    module=self.name,
                    target=host,
                    outcome=str(status) if status is not None else "no_response",
                    url=record.get("url") if record else None,
                )

            # A record whose identifying values (input/url) match none of the
            # hosts we sent still represents a real httpx result -- record it
            # under its own identifier rather than silently dropping it. A
            # record that matches a host via either key is already covered
            # by the per-host loop above, so it's excluded here.
            for record in parsed_records:
                record_url = record.get("url")
                record_hostname = urlparse(record_url).hostname if record_url else None
                record_keys = {
                    k for k in (record.get("input"), record_url, record_hostname) if k
                }
                if record_keys & hosts:
                    continue
                status = record.get("status_code")
                identifier = record.get("input") or record.get("url", "")
                audit.record(
                    module=self.name,
                    target=identifier,
                    outcome=str(status) if status is not None else "no_response",
                    url=record.get("url"),
                )

        return findings
