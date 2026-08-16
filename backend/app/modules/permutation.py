from app.modules.base import Finding, ReconModule, register_module

COMMON_WORDS = [
    "dev",
    "staging",
    "test",
    "uat",
    "beta",
    "admin",
    "api",
    "internal",
    "vpn",
    "mail",
    "old",
    "new",
    "demo",
    "backup",
]


@register_module
class SubdomainPermutationModule(ReconModule):
    # Generates candidates only; HttpxProbeModule (runs after) checks liveness.
    name = "subdomain_permutation"
    discovers_subdomains = True

    def run(self, target: str, context: dict) -> list[Finding]:
        labels = {
            label
            for label in (self._label(host, target) for host in context.get("subdomains", set()))
            if label is not None
        }

        candidates = {f"{word}.{target}" for word in COMMON_WORDS}
        for label in labels:
            for word in COMMON_WORDS:
                candidates.add(f"{word}-{label}.{target}")
                candidates.add(f"{label}-{word}.{target}")

        return [
            Finding(type="subdomain", value=c, data={"source": "permutation"})
            for c in sorted(candidates)
        ]

    @staticmethod
    def _label(hostname: str, target: str) -> str | None:
        suffix = "." + target
        if hostname.endswith(suffix):
            return hostname[: -len(suffix)]
        return None
