from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Finding:
    type: str
    value: str
    data: dict = field(default_factory=dict)


class ReconModule(ABC):
    name: str
    discovers_subdomains: bool = False

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
