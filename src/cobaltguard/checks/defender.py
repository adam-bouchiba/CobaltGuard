"""Interprète une réponse Get-MpComputerStatus sans exécuter PowerShell."""

from cobaltguard.models import CheckResult, Status


# Ce seuil pédagogique est une heuristique locale, pas une règle Microsoft.
SIGNATURE_WARNING_AGE_DAYS = 7
_FLAGS = {
    "AMServiceEnabled": "Service Microsoft Defender",
    "AntivirusEnabled": "Fonction antivirus Defender",
    "RealTimeProtectionEnabled": "Protection en temps réel",
}
_PASSIVE_MODES = {"Passive Mode", "SxS Passive Mode", "EDR Block Mode"}


def evaluate_defender(data: object) -> CheckResult:
    """Distingue une protection désactivée d'une collecte incomplète.

    Les booléens sont validés strictement : bool("false") vaut True en Python
    et ne doit donc jamais servir à interpréter une observation de sécurité.
    Un mode passif ne prouve pas qu'un autre antivirus protège le PC.
    """
    if not isinstance(data, dict):
        return CheckResult(
            check_id="defender",
            title="Microsoft Defender",
            status=Status.UNKNOWN,
            summary="Les informations Microsoft Defender sont indisponibles.",
            details=("La collecte ne contient pas un objet Defender exploitable.",),
            recommendations=("Consultez l'état des fournisseurs dans Sécurité Windows.",),
        )

    details: list[str] = []
    recommendations: list[str] = []
    incomplete = False
    disabled: list[str] = []
    for key, label in _FLAGS.items():
        value = data.get(key)
        if type(value) is not bool:
            incomplete = True
            details.append(f"{label} : information inconnue (absente ou invalide).")
        elif value:
            details.append(f"{label} : activé(e).")
        else:
            disabled.append(label)
            details.append(f"{label} : désactivé(e).")

    mode = data.get("AMRunningMode")
    normal_mode = mode == "Normal"
    passive_mode = isinstance(mode, str) and mode in _PASSIVE_MODES
    if normal_mode or passive_mode:
        details.append(f"Mode de fonctionnement : {mode}.")
    else:
        incomplete = True
        details.append("Mode de fonctionnement : information inconnue (absente ou non reconnue).")

    age = data.get("AntivirusSignatureAge")
    old_signatures = False
    if type(age) is int and age >= 0:
        old_signatures = age > SIGNATURE_WARNING_AGE_DAYS
        details.append(f"Âge des signatures : {age} jour(s).")
        if old_signatures:
            details.append(
                "Les signatures dépassent le seuil indicatif local de 7 jours ; "
                "ce seuil est une heuristique, pas une règle Microsoft."
            )
            recommendations.append("Vérifiez les mises à jour des signatures dans Sécurité Windows.")
    else:
        incomplete = True
        details.append("Âge des signatures : information inconnue (absente ou invalide).")

    if normal_mode and disabled:
        status = Status.FAIL
        summary = "Au moins une protection Defender est désactivée en mode Normal."
        recommendations.append(
            "Examinez les protections désactivées dans Sécurité Windows "
            "et vérifiez si cet état est attendu."
        )
    elif passive_mode:
        status = Status.WARNING
        summary = "Defender ne fonctionne pas en mode antivirus Normal."
        details.append(
            "Un mode passif ou EDR peut dépendre d'un antivirus tiers ou d'une politique ; "
            "cette collecte ne confirme ni sa présence ni sa protection effective."
        )
        recommendations.append(
            "Vérifiez les fournisseurs de sécurité et la protection effective dans Sécurité Windows."
        )
    elif old_signatures:
        status = Status.WARNING
        summary = "Les signatures Defender dépassent le seuil indicatif de 7 jours."
    elif incomplete:
        status = Status.UNKNOWN
        summary = "Les informations disponibles ne permettent pas de conclure sur Defender."
    else:
        status = Status.PASS
        summary = "Les protections Defender vérifiées sont actives en mode Normal."

    if incomplete:
        details.append("Contrôle incomplet : certaines informations restent inconnues.")
        recommendations.append(
            "Consultez Sécurité Windows pour les informations inconnues ; "
            "ce résultat ne garantit pas l'état global de la protection."
        )

    return CheckResult(
        check_id="defender",
        title="Microsoft Defender",
        status=status,
        summary=summary,
        details=tuple(details),
        recommendations=tuple(recommendations),
    )
