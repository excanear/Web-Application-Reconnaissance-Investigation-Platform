import subprocess

from app.modules.base import Finding, ReconModule, register_module


@register_module
class SubfinderModule(ReconModule):
    name = "subfinder"
    run_order = 10

    def run(self, target: str, context: dict) -> list[Finding]:
        audit = context.get("audit")
        try:
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
        except OSError as exc:
            # subfinder never even launched (e.g. the binary isn't
            # installed) -- distinguish "never attempted" from "attempted
            # and failed" so the audit trail doesn't imply a request was
            # made when none was.
            if audit is not None:
                audit.record(module=self.name, target=target, outcome=f"not_attempted: {exc}")
            raise
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            if audit is not None:
                audit.record(module=self.name, target=target, outcome=f"error: {exc}")
            raise

        subdomains = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        if audit is not None:
            audit.record(module=self.name, target=target, outcome=f"success ({len(subdomains)} found)")
        return [Finding(type="subdomain", value=s) for s in sorted(subdomains)]
