"""Rapport texte lisible avec le Bloc-notes, sans effet de bord."""

from __future__ import annotations

from datetime import datetime

from cobaltguard.models import CheckResult, Status


def _single_line(value: str) -> str:
    """Neutralise les retours ligne contenus dans les observations Windows."""
    return " ".join(value.split())


def render_text_report(
    results: tuple[CheckResult, ...], *, generated_at: datetime | None = None
) -> str:
    """Produire un rapport explicite, stable et imprimable (format UTF-8)."""
    timestamp = generated_at if generated_at is not None else datetime.now().astimezone()
    if timestamp.utcoffset() is None:
        raise ValueError("L'horodatage doit inclure un fuseau horaire.")

    counts = {status: sum(r.status is status for r in results) for status in Status}
    lines = [
        "COBALTGUARD | RAPPORT DE SECURITE WINDOWS",
        "=" * 62,
        f"Date de l'analyse : {timestamp.strftime('%d/%m/%Y %H:%M:%S %z')}",
        f"Nombre de controles : {len(results)}",
        "",
        "SYNTHESE",
        "-" * 62,
        *[f"{status.value:<8} : {counts[status]}" for status in Status],
        "",
        "IMPORTANT : audit indicatif en lecture seule. Les etats PASS ne",
        "garantissent pas l'absence de malware ou une securite globale.",
        "Un controle UNKNOWN/ERROR n'est pas un resultat conforme.",
        "",
    ]

    if not results:
        lines.extend(["Aucun controle n'a ete realise.", ""])

    for index, result in enumerate(results, start=1):
        lines.extend([
            "=" * 62,
            f"{index:02d} | {_single_line(result.title)} [{result.status.value}]",
            "=" * 62,
            f"Resume : {_single_line(result.summary)}",
            "",
            "OBSERVATIONS",
            "-" * 62,
        ])
        lines.extend(
            [f"- {_single_line(item)}" for item in result.details]
            or ["- Aucune observation supplementaire."]
        )
        lines.extend(["", "RECOMMANDATIONS", "-" * 62])
        lines.extend(
            [f"- {_single_line(item)}" for item in result.recommendations]
            or ["- Aucune recommandation supplementaire."]
        )
        lines.append("")

    lines.extend([
        "CONFIDENTIALITE",
        "-" * 62,
        "Ce rapport a ete genere localement et peut contenir des informations",
        "sur votre ordinateur. Relisez et anonymisez avant tout partage.",
        "",
        "CobaltGuard - Projet open source / outil d'audit, pas un antivirus.",
    ])
    return "\n".join(lines) + "\n"
