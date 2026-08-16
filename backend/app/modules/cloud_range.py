import ipaddress
import socket

from app.modules.base import Finding, ReconModule, register_module

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
        hosts = context.get("subdomains", set()) | {target}
        findings = []

        for host in sorted(hosts):
            try:
                ip = socket.gethostbyname(host)
            except OSError:
                continue

            provider = self._match_provider(ip)
            if provider is not None:
                findings.append(
                    Finding(type="cloud_asset", value=host, data={"ip": ip, "provider": provider})
                )

        return findings

    @staticmethod
    def _match_provider(ip: str) -> str | None:
        address = ipaddress.ip_address(ip)
        for provider, network in CLOUD_RANGES:
            if address in network:
                return provider
        return None
