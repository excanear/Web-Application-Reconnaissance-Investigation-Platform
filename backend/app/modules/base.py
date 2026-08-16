from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Finding:
    type: str
    value: str
    data: dict = field(default_factory=dict)


class ReconModule(ABC):
    name: str

    @abstractmethod
    def run(self, target: str, context: dict) -> list[Finding]:
        ...
