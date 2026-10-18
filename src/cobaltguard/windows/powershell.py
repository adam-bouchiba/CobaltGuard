"""Exécuter seulement les deux collectes PowerShell autorisées.

Le code appelant choisit une requête prédéfinie, jamais un script libre.
Windows PowerShell 5.1 est fourni avec la cible initiale Windows 11.
"""

import json
import math
import os
from pathlib import Path
import platform
import subprocess
from enum import Enum


class PowerShellQuery(Enum):
    DEFENDER = "defender"
    FIREWALL = "firewall"


class PowerShellError(Exception):
    """Erreur de la frontière entre Python et PowerShell."""


class PowerShellUnavailableError(PowerShellError):
    """Plateforme, exécutable ou commande indisponible."""


class PowerShellAccessDeniedError(PowerShellError):
    """La session actuelle n'a pas accès à cette information."""


class PowerShellTimeoutError(PowerShellError):
    """La collecte a dépassé son délai maximal."""


class PowerShellExecutionError(PowerShellError):
    """Le processus ou une commande PowerShell a échoué."""


class PowerShellDataError(PowerShellError):
    """La sortie ne respecte pas le contrat JSON de collecte."""


_QUERIES = {
    PowerShellQuery.DEFENDER: """
        Get-MpComputerStatus -ErrorAction Stop |
            Select-Object AMServiceEnabled, AntivirusEnabled,
                RealTimeProtectionEnabled, AntivirusSignatureAge, AMRunningMode
    """,
    PowerShellQuery.FIREWALL: """
        # Enabled est une enum GpoBoolean : NotConfigured ne doit pas devenir True.
        @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            Select-Object Name, @{Name='Enabled'; Expression={ [string]$_.Enabled }})
    """,
}

_PREFIX = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
try {
    $data = & {
"""

_SUFFIX = """
    ConvertTo-Json -InputObject @{ ok = $true; data = $data } -Depth 5 -Compress
    exit 0
} catch {
    $kind = 'execution'
    $category = [string]$_.CategoryInfo.Category
    if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
        $kind = 'unavailable'
    } elseif ($category -in @('PermissionDenied', 'SecurityError') -or
              $_.Exception -is [System.UnauthorizedAccessException] -or
              $_.Exception.HResult -eq -2147024891) {
        $kind = 'denied'
    }
    ConvertTo-Json -InputObject @{
        ok = $false
        error = @{ kind = $kind; message = $_.Exception.Message }
    } -Depth 5 -Compress
    exit 1
}
"""


def _windows_powershell() -> Path:
    """Utiliser l'exécutable système, sans rechercher un programme dans PATH."""
    if platform.system() != "Windows":
        raise PowerShellUnavailableError("Ce contrôle nécessite Windows.")
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise PowerShellUnavailableError("Le répertoire système Windows est introuvable.")
    executable = Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    if not executable.is_file():
        raise PowerShellUnavailableError("Windows PowerShell est introuvable.")
    return executable


class PowerShellRunner:
    """Collecteur synchrone : le moteur peut l'utiliser sans importer Tkinter."""

    def __init__(self, timeout: float = 15.0) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Le délai doit être un nombre positif et fini.")
        self.timeout = timeout

    def run(self, query: PowerShellQuery) -> object:
        """Retourner les données JSON ou une erreur métier explicite.

        subprocess.run tue et attend le processus si le délai expire.
        Aucun profil PowerShell, shell intermédiaire ou élévation de droits.
        """
        if not isinstance(query, PowerShellQuery):
            raise ValueError("Seules les requêtes PowerShell prédéfinies sont autorisées.")
        executable = _windows_powershell()
        # PowerShell déroule les listes dans le pipeline. Forcer un tableau ici
        # conserve le contrat pare-feu, même avec zéro ou un seul profil renvoyé.
        normalize = "$data = @($data)\n" if query is PowerShellQuery.FIREWALL else ""
        script = _PREFIX + _QUERIES[query] + "\n    }\n" + normalize + _SUFFIX
        arguments = [
            str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script
        ]
        try:
            completed = subprocess.run(
                arguments,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise PowerShellTimeoutError(
                f"La collecte a dépassé le délai de {self.timeout:g} secondes."
            ) from exc
        except PermissionError as exc:
            raise PowerShellAccessDeniedError("L'exécution de PowerShell est refusée.") from exc
        except FileNotFoundError as exc:
            raise PowerShellUnavailableError("Windows PowerShell est introuvable.") from exc
        except OSError as exc:
            raise PowerShellExecutionError(f"Impossible de démarrer PowerShell : {exc}") from exc

        try:
            payload = json.loads(completed.stdout.lstrip("\ufeff"))
        except (json.JSONDecodeError, ValueError) as exc:
            if completed.returncode != 0:
                message = completed.stderr.strip()[:1000] or "Aucun détail fourni."
                raise PowerShellExecutionError(
                    f"PowerShell a quitté avec le code {completed.returncode} : {message}"
                ) from exc
            raise PowerShellDataError("PowerShell n'a pas renvoyé un document JSON valide.") from exc

        if not isinstance(payload, dict) or type(payload.get("ok")) is not bool:
            raise PowerShellDataError("La réponse PowerShell a une structure inattendue.")
        if payload["ok"]:
            if completed.returncode != 0:
                raise PowerShellExecutionError(
                    f"PowerShell a quitté avec le code {completed.returncode}."
                )
            if "data" not in payload:
                raise PowerShellDataError("La réponse PowerShell ne contient pas de données.")
            return payload["data"]

        error = payload.get("error")
        if (
            not isinstance(error, dict)
            or not isinstance(error.get("message"), str)
            or not isinstance(error.get("kind"), str)
        ):
            raise PowerShellDataError("Le détail de l'erreur PowerShell est invalide.")
        message = error["message"].strip()[:1000] or "Aucun détail fourni."
        error_class = {
            "unavailable": PowerShellUnavailableError,
            "denied": PowerShellAccessDeniedError,
            "execution": PowerShellExecutionError,
        }.get(error.get("kind"))
        if error_class is None:
            raise PowerShellDataError("Le type d'erreur PowerShell est inconnu.")
        raise error_class(message)
