"""Interprète les profils renvoyés par Get-NetFirewallProfile."""

from cobaltguard.models import CheckResult, Status


_PROFILES = {"Domain": "Domaine", "Private": "Privé", "Public": "Public"}
_SCOPE = (
    "Ces états ne déterminent ni le profil réseau actuellement utilisé "
    "ni la qualité des règles du pare-feu."
)


def evaluate_firewall(data: object) -> CheckResult:
    """Vérifie les trois profils sans convertir GpoBoolean en booléen Python.

    La collecte doit sérialiser Enabled en texte : NotConfigured représente une
    information indéterminée et ne doit pas être traité comme True ou False.
    """
    if not isinstance(data, list):
        return CheckResult(
            check_id="firewall",
            title="Pare-feu Windows",
            status=Status.UNKNOWN,
            summary="Les informations du pare-feu sont indisponibles.",
            details=("La collecte ne contient pas une liste de profils exploitable.", _SCOPE),
            recommendations=("Consultez Pare-feu et protection réseau dans Sécurité Windows.",),
        )

    details: list[str] = []
    seen: set[str] = set()
    incomplete = False
    disabled = False
    for profile in data:
        if not isinstance(profile, dict):
            incomplete = True
            details.append("Une entrée de profil est invalide et reste inconnue.")
            continue

        name = profile.get("Name")
        if not isinstance(name, str) or name not in _PROFILES:
            incomplete = True
            details.append("Une entrée contient un nom de profil absent ou non reconnu.")
            continue

        label = _PROFILES[name]
        if name in seen:
            incomplete = True
            details.append(f"Profil {label} : plusieurs entrées reçues, résultat ambigu.")
        seen.add(name)
        enabled = profile.get("Enabled")
        if enabled == "True":
            details.append(f"Profil {label} : pare-feu activé.")
        elif enabled == "False":
            disabled = True
            details.append(f"Profil {label} : pare-feu désactivé.")
        elif enabled == "NotConfigured":
            incomplete = True
            details.append(f"Profil {label} : état NotConfigured, protection indéterminée.")
        else:
            incomplete = True
            details.append(f"Profil {label} : état inconnu (absent ou invalide).")

    for name, label in _PROFILES.items():
        if name not in seen:
            incomplete = True
            details.append(f"Profil {label} : information absente.")

    recommendations: list[str] = []
    if disabled:
        status = Status.FAIL
        summary = "Au moins un profil du pare-feu Windows est désactivé."
        recommendations.append(
            "Examinez les profils désactivés dans Sécurité Windows "
            "et vérifiez si cet état est attendu."
        )
    elif incomplete:
        status = Status.UNKNOWN
        summary = "L'état des trois profils du pare-feu ne peut pas être confirmé."
    else:
        status = Status.PASS
        summary = "Les profils Domaine, Privé et Public du pare-feu sont activés."

    if incomplete:
        details.append("Contrôle incomplet : certaines informations sont inconnues ou ambiguës.")
        recommendations.append(
            "Vérifiez les profils inconnus ou ambigus dans Pare-feu et protection réseau."
        )
    details.append(_SCOPE)
    return CheckResult(
        check_id="firewall",
        title="Pare-feu Windows",
        status=status,
        summary=summary,
        details=tuple(details),
        recommendations=tuple(recommendations),
    )
