"""Les réponses simulées rendent les règles testables sans Windows."""

import pytest

from cobaltguard.checks.defender import evaluate_defender
from cobaltguard.models import Status


@pytest.fixture
def healthy_defender():
    return {
        "AMServiceEnabled": True,
        "AntivirusEnabled": True,
        "RealTimeProtectionEnabled": True,
        "AntivirusSignatureAge": 0,
        "AMRunningMode": "Normal",
    }


def test_active_defender_passes(healthy_defender):
    result = evaluate_defender(healthy_defender)
    assert result.status is Status.PASS
    assert result.check_id == "defender"


@pytest.mark.parametrize("field", ["AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled"])
def test_disabled_protection_in_normal_mode_fails(healthy_defender, field):
    healthy_defender[field] = False
    result = evaluate_defender(healthy_defender)
    assert result.status is Status.FAIL
    assert result.recommendations


@pytest.mark.parametrize("age, expected", [(7, Status.PASS), (8, Status.WARNING)])
def test_signature_age_threshold_is_explicit(healthy_defender, age, expected):
    healthy_defender["AntivirusSignatureAge"] = age
    assert evaluate_defender(healthy_defender).status is expected


@pytest.mark.parametrize("mode", ["Passive Mode", "SxS Passive Mode", "EDR Block Mode"])
def test_passive_modes_warn_without_claiming_third_party_protection(healthy_defender, mode):
    healthy_defender.update(AMRunningMode=mode, RealTimeProtectionEnabled=False)
    result = evaluate_defender(healthy_defender)
    assert result.status is Status.WARNING
    assert any("ne confirme ni sa présence" in detail for detail in result.details)


@pytest.mark.parametrize("mode", [None, "Future mode", [], 1])
def test_unknown_mode_does_not_turn_disabled_flags_into_failure(healthy_defender, mode):
    healthy_defender.update(AMRunningMode=mode, RealTimeProtectionEnabled=False)
    assert evaluate_defender(healthy_defender).status is Status.UNKNOWN


@pytest.mark.parametrize("value", [None, "false", "true", 0, 1, [], {}])
def test_flags_require_real_booleans(healthy_defender, value):
    healthy_defender["RealTimeProtectionEnabled"] = value
    assert evaluate_defender(healthy_defender).status is Status.UNKNOWN


@pytest.mark.parametrize("value", [None, -1, True, "8", 0.5])
def test_signature_age_requires_nonnegative_integer(healthy_defender, value):
    healthy_defender["AntivirusSignatureAge"] = value
    assert evaluate_defender(healthy_defender).status is Status.UNKNOWN


@pytest.mark.parametrize("data", [None, [], "", {}, 42])
def test_missing_or_malformed_response_is_unknown(data):
    assert evaluate_defender(data).status is Status.UNKNOWN


@pytest.mark.parametrize("field", ["AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "AntivirusSignatureAge", "AMRunningMode"])
def test_every_required_field_must_be_present_to_pass(healthy_defender, field):
    del healthy_defender[field]
    assert evaluate_defender(healthy_defender).status is Status.UNKNOWN


def test_confirmed_failure_is_preserved_when_signature_age_missing(healthy_defender):
    healthy_defender["RealTimeProtectionEnabled"] = False
    del healthy_defender["AntivirusSignatureAge"]
    result = evaluate_defender(healthy_defender)
    assert result.status is Status.FAIL
    assert any("incomplet" in detail for detail in result.details)
    assert any("inconnues" in recommendation for recommendation in result.recommendations)


def test_confirmed_warning_is_preserved_with_missing_flags(healthy_defender):
    healthy_defender["AntivirusSignatureAge"] = 8
    del healthy_defender["RealTimeProtectionEnabled"]
    result = evaluate_defender(healthy_defender)
    assert result.status is Status.WARNING
    assert any("incomplet" in detail for detail in result.details)


def test_passive_mode_warns_with_partial_collection():
    result = evaluate_defender({"AMRunningMode": "Passive Mode"})
    assert result.status is Status.WARNING
    assert any("incomplet" in detail for detail in result.details)
