"""Tests de l'export JSON sans accès à Windows ni au système de fichiers."""

import json
from datetime import datetime, timezone

import pytest

from cobaltguard.models import CheckResult, Status
from cobaltguard.reporting.json_report import render_json_report


def test_renders_one_complete_check_and_unicode():
    result = CheckResult(
        check_id="defender", title="Sécurité Windows", status=Status.WARNING,
        summary="À vérifier", details=("Signature âgée",),
        recommendations=("Mettre à jour",),
    )
    data = json.loads(render_json_report(
        (result,), generated_at=datetime(2026, 10, 18, 16, 0, tzinfo=timezone.utc)
    ))
    assert data["schema_version"] == 1
    assert data["generated_at"] == "2026-10-18T16:00:00+00:00"
    assert data["checks"][0] == {
        "id": "defender", "title": "Sécurité Windows", "status": "WARNING",
        "summary": "À vérifier", "details": ["Signature âgée"],
        "recommendations": ["Mettre à jour"],
    }


def test_empty_result_set_is_valid_report():
    document = json.loads(render_json_report((), generated_at=datetime.now(timezone.utc)))
    assert document["checks"] == []


def test_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="fuseau"):
        render_json_report((), generated_at=datetime(2026, 1, 1))
