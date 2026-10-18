"""Sérialisation locale d'un audit en JSON, indépendante de l'interface."""

from __future__ import annotations

from datetime import datetime, timezone
import json

from cobaltguard.models import CheckResult


def render_json_report(
    results: tuple[CheckResult, ...], *, generated_at: datetime | None = None
) -> str:
    """Retourne un rapport déterministe à horodatage fixé (sans écriture disque).

    La sauvegarde n'est déclenchée que par une action explicite de l'utilisateur.
    Les détails peuvent inclure des noms de machines ou chemins locaux :
    ne pas les publier sans relecture.
    """
    timestamp = generated_at if generated_at is not None else datetime.now(timezone.utc)
    if timestamp.utcoffset() is None:
        raise ValueError("L'horodatage doit inclure un fuseau horaire.")

    report = {
        "schema_version": 1,
        "application": "CobaltGuard",
        "generated_at": timestamp.isoformat(timespec="seconds"),
        "disclaimer": (
            "Audit indicatif en lecture seule. Aucun résultat n'atteste "
            "à lui seul de l'absence de logiciel malveillant."
        ),
        "checks": [
            {
                "id": item.check_id,
                "title": item.title,
                "status": item.status.value,
                "summary": item.summary,
                "details": list(item.details),
                "recommendations": list(item.recommendations),
            }
            for item in results
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
