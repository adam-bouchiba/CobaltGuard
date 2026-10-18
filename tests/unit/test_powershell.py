"""Tester la frontière processus sans exécuter de commande Windows."""

import json
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

from cobaltguard.windows import powershell as ps


@pytest.fixture
def process(monkeypatch):
    monkeypatch.setattr(ps, "_windows_powershell", lambda: Path("powershell.exe"))
    run = Mock()
    monkeypatch.setattr(ps.subprocess, "run", run)
    return run


def response(payload, returncode=0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=json.dumps(payload), stderr=""
    )


def test_json_data_is_returned_and_process_is_noninteractive(process):
    data = {"AMServiceEnabled": True}
    process.return_value = response({"ok": True, "data": data})
    assert ps.PowerShellRunner(timeout=2).run(ps.PowerShellQuery.DEFENDER) == data
    arguments = process.call_args.args[0]
    options = process.call_args.kwargs
    assert "-NoProfile" in arguments
    assert "-NonInteractive" in arguments
    assert "-ExecutionPolicy" not in arguments
    assert options["shell"] is False
    assert options["stdin"] == subprocess.DEVNULL
    assert options["timeout"] == 2
    assert options["encoding"] == "utf-8"


def test_free_form_commands_are_rejected_before_starting_process(process):
    with pytest.raises(ValueError, match="prédéfinies"):
        ps.PowerShellRunner().run("Get-MpComputerStatus; Remove-Item example")
    process.assert_not_called()


def test_timeout_becomes_an_explicit_collection_error(process):
    process.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=2)
    with pytest.raises(ps.PowerShellTimeoutError, match="2 secondes"):
        ps.PowerShellRunner(timeout=2).run(ps.PowerShellQuery.DEFENDER)


@pytest.mark.parametrize(
    "kind, exception",
    [
        ("denied", ps.PowerShellAccessDeniedError),
        ("unavailable", ps.PowerShellUnavailableError),
        ("execution", ps.PowerShellExecutionError),
    ],
)
def test_structured_command_errors_are_classified(process, kind, exception):
    process.return_value = response(
        {"ok": False, "error": {"kind": kind, "message": "Erreur simulée."}},
        returncode=1,
    )
    with pytest.raises(exception, match="Erreur simulée"):
        ps.PowerShellRunner().run(ps.PowerShellQuery.FIREWALL)


@pytest.mark.parametrize(
    "cause, exception",
    [
        (PermissionError("Refus"), ps.PowerShellAccessDeniedError),
        (FileNotFoundError("Absent"), ps.PowerShellUnavailableError),
        (OSError("Processus indisponible"), ps.PowerShellExecutionError),
    ],
)
def test_process_start_failures_are_classified(process, cause, exception):
    process.side_effect = cause
    with pytest.raises(exception):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)


@pytest.mark.parametrize("output", ["", "not JSON", "{broken"])
def test_invalid_json_is_an_error_instead_of_missing_security_data(process, output):
    process.return_value = subprocess.CompletedProcess([], 0, output, "")
    with pytest.raises(ps.PowerShellDataError):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"ok": "true", "data": {}},
        {"ok": True},
        {"ok": False},
        {"ok": False, "error": {"kind": [], "message": "Refus"}},
        {"ok": False, "error": {"kind": "unexpected", "message": "Refus"}},
    ],
)
def test_invalid_envelopes_are_explicit_errors(process, payload):
    process.return_value = response(payload)
    with pytest.raises(ps.PowerShellDataError):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)


def test_nonzero_exit_never_becomes_success(process):
    process.return_value = response({"ok": True, "data": {}}, returncode=1)
    with pytest.raises(ps.PowerShellExecutionError):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)


def test_startup_error_without_json_includes_diagnostic(process):
    process.return_value = subprocess.CompletedProcess([], 1, "", "Script bloqué")
    with pytest.raises(ps.PowerShellExecutionError, match="Script bloqué"):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)


def test_utf8_bom_and_accents_are_supported(process):
    process.return_value = subprocess.CompletedProcess(
        [], 0, '\ufeff{"ok":true,"data":{"message":"État inconnu"}}', ""
    )
    assert ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER) == {
        "message": "État inconnu"
    }


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_timeout_must_be_positive_and_finite(timeout):
    with pytest.raises(ValueError):
        ps.PowerShellRunner(timeout=timeout)


def test_non_windows_machine_is_unavailable(monkeypatch):
    monkeypatch.setattr(ps.platform, "system", lambda: "Linux")
    with pytest.raises(ps.PowerShellUnavailableError, match="nécessite Windows"):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)


def test_missing_system_executable_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(ps.platform, "system", lambda: "Windows")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    with pytest.raises(ps.PowerShellUnavailableError, match="introuvable"):
        ps.PowerShellRunner().run(ps.PowerShellQuery.DEFENDER)
