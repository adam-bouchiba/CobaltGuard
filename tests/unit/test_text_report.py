"""Tests de l'export texte sans environnement graphique ni accès à Windows."""

from datetime import datetime, timezone

import pytest

from cobaltguard.models import CheckResult, Status
from cobaltguard.reporting.text_report import render_text_report


FIXED_TIME = datetime(2026, 10, 18, 17, 30, tzinfo=timezone.utc)


def test_text_report_contains_status_details_and_recommendations():
    result = CheckResult(
        check_id="firewall",
        title="Pare-feu Windows",
        status=Status.FAIL,
        summary="Profil Public désactivé.",
        details=("Profil Public : désactivé.",),
        recommendations=("Vérifier la configuration.",),
    )
    report = render_text_report((result,), generated_at=FIXED_TIME)
    assert "18/10/2026 17:30:00 +0000" in report
    assert "01 | Pare-feu Windows [FAIL]" in report
    assert "FAIL     : 1" in report
    assert "- Profil Public : désactivé." in report
    assert "- Vérifier la configuration." in report
    assert "CONFIDENTIALITE" in report
    assert report.endswith("\n")


def test_unknown_is_not_reported_as_pass():
    result = CheckResult(
        check_id="defender", title="Defender",
        status=Status.UNKNOWN, summary="Données indisponibles.",
    )
    report = render_text_report((result,), generated_at=FIXED_TIME)
    assert "UNKNOWN  : 1" in report
    assert "PASS     : 0" in report
    assert "garantissent pas" in report


def test_empty_results_are_explicit():
    report = render_text_report((), generated_at=FIXED_TIME)
    assert "Aucun controle n'a ete realise." in report


def test_newline_in_diagnostics_cannot_forge_report_sections():
    result = CheckResult(
        check_id="audit", title="Un\ntitre",
        status=Status.ERROR,
        summary="Erreur\ntechnique",
        details=("Ligne 1\nLigne 2",),
    )
    report = render_text_report((result,), generated_at=FIXED_TIME)
    assert "Un titre [ERROR]" in report
    assert "Ligne 1 Ligne 2" in report
    assert "Erreur technique" in report


def test_naive_datetime_is_rejected():
    with pytest.raises(ValueError, match="fuseau"):
        render_text_report((), generated_at=datetime(2026, 10, 18))
