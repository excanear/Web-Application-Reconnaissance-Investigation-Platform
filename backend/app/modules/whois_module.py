import whois

from app.modules.base import Finding, ReconModule


class WhoisModule(ReconModule):
    name = "whois"

    def run(self, target: str, context: dict) -> list[Finding]:
        record = whois.whois(target)
        data = {
            "registrar": record.get("registrar"),
            "creation_date": str(record.get("creation_date")),
            "expiration_date": str(record.get("expiration_date")),
            "name_servers": record.get("name_servers"),
        }
        return [Finding(type="whois", value=target, data=data)]
