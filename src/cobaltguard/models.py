"""Contrat partagé par le moteur et ses interfaces, sans dépendance graphique."""

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    """Conclusion du contrôle, et non score de sécurité de tout le PC."""

    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


@dataclass(frozen=True)
class CheckResult:
    """Résultat immuable : un travailleur peut le transmettre à l'interface.

    UNKNOWN indique des données insuffisantes ou inaccessibles ; ERROR indique
    un échec technique. Un FAIL n'est pas une preuve de compromission.
    """

    check_id: str
    title: str
    status: Status
    summary: str
    details: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
