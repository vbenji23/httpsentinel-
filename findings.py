"""Structures de données partagées : résultats (Finding) et niveaux de sévérité."""

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    """Niveau de sévérité d'un résultat, du plus grave au purement informatif."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    OK = "OK"

    @property
    def rank(self) -> int:
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}
        return order[self.value]


@dataclass
class Finding:
    """Un constat produit par un check."""

    check: str          # nom du module (ex. "headers")
    title: str          # résumé court
    severity: Severity
    detail: str = ""    # explication / valeur observée
    recommendation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanContext:
    """Contexte passé à chaque check : l'URL cible et les options."""

    url: str
    insecure: bool = False
    timeout: float = 10.0
    findings: list = field(default_factory=list)
