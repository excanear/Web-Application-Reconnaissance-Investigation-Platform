import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from app.modules.base import Finding, ReconModule, prioritized_hosts, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_MAX_WORKERS = 1

# Small illustrative sample of public cloud ranges, not an authoritative or
# exhaustive list (each provider publishes machine-readable full lists that
# a future module could sync periodically instead).
CLOUD_RANGES = [
    ("aws", ipaddress.ip_network("3.5.128.0/18")),
    ("aws", ipaddress.ip_network("52.0.0.0/11")),
    ("gcp", ipaddress.ip_network("34.64.0.0/10")),
    ("gcp", ipaddress.ip_network("35.184.0.0/13")),
    ("azure", ipaddress.ip_network("20.0.0.0/8")),
    ("azure", ipaddress.ip_network("40.64.0.0/10")),
]


@register_module
class CloudRangeModule(ReconModule):
    name = "cloud_range"

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = prioritized_hosts(context, target)
        scope = context.get("scope")
        audit = context.get("audit")
        max_workers = context.get("max_workers", DEFAULT_MAX_WORKERS)
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        findings = []

        for batch_start in range(0, len(hosts), max_workers):
            batch = hosts[batch_start:batch_start + max_workers]

            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                results = list(
                    executor.map(lambda host: self._resolve_host(host, limiter, audit), batch)
                )

            breaker_tripped = False
            for offset, (host, (ip, error)) in enumerate(zip(batch, results)):
                index = batch_start + offset

                if error is not None:
                    if breaker.record_failure():
                        findings.append(
                            Finding(
                                type="circuit_breaker_tripped",
                                value=host,
                                data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                            )
                        )
                        breaker_tripped = True
                        break
                    continue

                breaker.record_success()

                if scope is not None and not is_in_scope(host, ip, scope):
                    findings.append(
                        Finding(type="out_of_scope", value=host, data={"module": self.name})
                    )
                    continue

                provider = self._match_provider(ip)
                if provider is not None:
                    findings.append(
                        Finding(type="cloud_asset", value=host, data={"ip": ip, "provider": provider})
                    )

            if breaker_tripped:
                break

        return findings

    def _resolve_host(
        self, host: str, limiter: RateLimiter, audit
    ) -> tuple[str | None, str | None]:
        limiter.wait()
        try:
            ip = socket.gethostbyname(host)
        except OSError as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}")
            return None, str(exc)
        if audit is not None:
            audit.record(module=self.name, target=host, outcome=f"resolved: {ip}")
        return ip, None

    @staticmethod
    def _match_provider(ip: str) -> str | None:
        address = ipaddress.ip_address(ip)
        for provider, network in CLOUD_RANGES:
            if address in network:
                return provider
        return None
