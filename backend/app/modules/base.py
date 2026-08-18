from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Finding:
    type: str
    value: str
    data: dict = field(default_factory=dict)


class ReconModule(ABC):
    name: str
    # Orchestrator runs modules in ascending run_order, threading context
    # through each: 10=discovery, 50=analysis (default), 90=correlation.
    run_order: int = 50
    # Active modules send probes/requests straight at the target and
    # require the scan-level active-modules confirmation to run.
    is_active: bool = False

    # Scope contract: context.get("scope") returns None only when a module
    # is invoked directly outside the orchestrator (e.g. a unit test calling
    # .run(target, {})). The real orchestrator always populates context["scope"]
    # with a dict (scan.project.scope or {}) for every scan. Modules that guard
    # their scope checks with `if scope is not None and not is_in_scope(...)`
    # are treating a missing key as "no restriction" purely for that
    # backward-compatibility case -- it is NOT a safe default to rely on, and a
    # real dict scope (even {}) fails closed. Do not assume a missing "scope"
    # key means anything other than "not running under the orchestrator".

    # Audit contract: context.get("audit") returns None only when a module is
    # invoked directly outside the orchestrator (e.g. a unit test calling
    # .run(target, {})). The real orchestrator always populates context["audit"]
    # with a real AuditLog instance for every scan. Modules that make a real
    # network call guard with `if audit is not None:` before calling
    # `.record(...)` -- same pattern as the scope contract above.
    @abstractmethod
    def run(self, target: str, context: dict) -> list[Finding]:
        ...


MODULE_REGISTRY: dict[str, type[ReconModule]] = {}


def register_module(cls: type[ReconModule]) -> type[ReconModule]:
    """Class decorator: adds a ReconModule subclass to MODULE_REGISTRY by
    its .name. Modules must be imported (see app/modules/__init__.py) for
    registration to happen."""
    MODULE_REGISTRY[cls.name] = cls
    return cls
