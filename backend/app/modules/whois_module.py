import whois

from app.modules.base import Finding, ReconModule, register_module
from app.scope import is_in_scope


@register_module
class WhoisModule(ReconModule):
    name = "whois"

    def run(self, target: str, context: dict) -> list[Finding]:
        scope = context.get("scope")
        if scope is not None and not is_in_scope(target, None, scope):
            return [Finding(type="out_of_scope", value=target, data={"module": self.name})]

        audit = context.get("audit")
        try:
            record = whois.whois(target)
        except Exception as exc:
            if audit is not None:
                audit.record(module=self.name, target=target, outcome=f"error: {exc}")
            raise

        if audit is not None:
            audit.record(module=self.name, target=target, outcome="success")

        data = {
            "registrar": record.get("registrar"),
            "creation_date": str(record.get("creation_date")),
            "expiration_date": str(record.get("expiration_date")),
            "name_servers": record.get("name_servers"),
        }
        return [Finding(type="whois", value=target, data=data)]
