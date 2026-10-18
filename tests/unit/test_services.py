"""Un faux collecteur remplace Windows ; les vraies règles restent exécutées."""

import pytest

from cobaltguard.models import Status
from cobaltguard.services import AuditService
from cobaltguard.windows.powershell import (
    PowerShellAccessDeniedError,
    PowerShellDataError,
    PowerShellExecutionError,
    PowerShellQuery,
    PowerShellTimeoutError,
    PowerShellUnavailableError,
)


class FakeCollector:
    def __init__(self, defender):
        self.defender = defender
        self.calls = []

    def run(self, query):
        self.calls.append(query)
        if query is PowerShellQuery.DEFENDER:
            if isinstance(self.defender, Exception):
                raise self.defender
            return self.defender
        return [
            {"Name": name, "Enabled": "True"}
            for name in ("Domain", "Private", "Public")
        ]


def test_two_successful_collections_produce_independent_results():
    collector = FakeCollector(
        {
            "AMServiceEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "AntivirusSignatureAge": 0,
            "AMRunningMode": "Normal",
        }
    )
    results = AuditService(collector).run()
    assert [(result.check_id, result.status) for result in results] == [
        ("defender", Status.PASS), ("firewall", Status.PASS)
    ]
    assert collector.calls == [PowerShellQuery.DEFENDER, PowerShellQuery.FIREWALL]


@pytest.mark.parametrize(
    "error, expected",
    [
        (PowerShellAccessDeniedError("Accès refusé"), Status.UNKNOWN),
        (PowerShellUnavailableError("Commande absente"), Status.UNKNOWN),
        (PowerShellTimeoutError("Délai dépassé"), Status.ERROR),
        (PowerShellExecutionError("Échec de commande"), Status.ERROR),
        (PowerShellDataError("JSON invalide"), Status.ERROR),
    ],
)
def test_first_collection_error_does_not_prevent_second_check(error, expected):
    collector = FakeCollector(error)
    defender, firewall = AuditService(collector).run()
    assert defender.status is expected
    assert str(error) in defender.details
    assert defender.recommendations
    assert firewall.status is Status.PASS
    assert collector.calls == [PowerShellQuery.DEFENDER, PowerShellQuery.FIREWALL]


def test_empty_security_data_is_unknown_not_a_success():
    defender, firewall = AuditService(FakeCollector(None)).run()
    assert defender.status is Status.UNKNOWN
    assert firewall.status is Status.PASS
