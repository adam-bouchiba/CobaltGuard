"""Coordonner les contrôles sans dépendre de l'interface ou des threads."""

from typing import Protocol

from cobaltguard.checks.defender import evaluate_defender
from cobaltguard.checks.firewall import evaluate_firewall
from cobaltguard.models import CheckResult, Status
from cobaltguard.windows.powershell import (
    PowerShellAccessDeniedError,
    PowerShellError,
    PowerShellQuery,
    PowerShellRunner,
    PowerShellUnavailableError,
)


class Collector(Protocol):
    """Un vrai collecteur et un faux de test offrent la même petite interface."""

    def run(self, query: PowerShellQuery) -> object: ...


class AuditService:
    def __init__(self, runner: Collector | None = None) -> None:
        self._runner = runner if runner is not None else PowerShellRunner()

    def run(self) -> tuple[CheckResult, ...]:
        """L'échec d'une collecte n'empêche pas l'exécution du contrôle suivant."""
        results = []
        checks = (
            (PowerShellQuery.DEFENDER, "Microsoft Defender", evaluate_defender),
            (PowerShellQuery.FIREWALL, "Pare-feu Windows", evaluate_firewall),
        )
        for query, title, evaluate in checks:
            try:
                result = evaluate(self._runner.run(query))
            except (PowerShellUnavailableError, PowerShellAccessDeniedError) as exc:
                result = CheckResult(
                    check_id=query.value,
                    title=title,
                    status=Status.UNKNOWN,
                    summary="Les informations nécessaires ne sont pas accessibles.",
                    details=(str(exc),),
                    recommendations=(
                        "Vérifier manuellement ce point dans Sécurité Windows. "
                        "Aucun changement de droits n'a été demandé.",
                    ),
                )
            except PowerShellError as exc:
                result = CheckResult(
                    check_id=query.value,
                    title=title,
                    status=Status.ERROR,
                    summary="La collecte n'a pas pu aboutir.",
                    details=(str(exc),),
                    recommendations=(
                        "Consulter le détail de l'erreur et vérifier ce point dans Sécurité Windows.",
                    ),
                )
            results.append(result)
        return tuple(results)
