"""Vérifie les profils simulés, dont l'énumération Windows NotConfigured."""

import pytest

from cobaltguard.checks.firewall import evaluate_firewall
from cobaltguard.models import Status


@pytest.fixture
def enabled_profiles():
    return [{"Name": name, "Enabled": "True"} for name in ("Domain", "Private", "Public")]


def test_all_three_enabled_profiles_pass(enabled_profiles):
    result = evaluate_firewall(enabled_profiles)
    assert result.status is Status.PASS
    assert result.check_id == "firewall"
    assert any("profil réseau actuellement utilisé" in detail for detail in result.details)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_each_disabled_profile_fails(enabled_profiles, index):
    enabled_profiles[index]["Enabled"] = "False"
    result = evaluate_firewall(enabled_profiles)
    assert result.status is Status.FAIL
    assert result.recommendations


@pytest.mark.parametrize("value", ["NotConfigured", None, True, False, 0, 1, "false", [], {}])
def test_unresolved_or_malformed_enabled_state_is_unknown(enabled_profiles, value):
    enabled_profiles[0]["Enabled"] = value
    assert evaluate_firewall(enabled_profiles).status is Status.UNKNOWN


@pytest.mark.parametrize("data", [None, {}, "", [], 0, {"Name": "Domain", "Enabled": "True"}])
def test_missing_or_malformed_response_is_unknown(data):
    assert evaluate_firewall(data).status is Status.UNKNOWN


@pytest.mark.parametrize("index", [0, 1, 2])
def test_missing_profile_prevents_pass(enabled_profiles, index):
    enabled_profiles.pop(index)
    result = evaluate_firewall(enabled_profiles)
    assert result.status is Status.UNKNOWN
    assert any("absente" in detail for detail in result.details)


def test_disabled_profile_remains_failure_with_missing_profiles():
    result = evaluate_firewall([{"Name": "Public", "Enabled": "False"}])
    assert result.status is Status.FAIL
    assert any("incomplet" in detail for detail in result.details)
    assert any("inconnus" in recommendation for recommendation in result.recommendations)


def test_duplicate_profiles_prevent_pass(enabled_profiles):
    enabled_profiles.append({"Name": "Domain", "Enabled": "True"})
    result = evaluate_firewall(enabled_profiles)
    assert result.status is Status.UNKNOWN
    assert any("ambigu" in detail for detail in result.details)


def test_disabled_duplicate_is_reported_with_ambiguity(enabled_profiles):
    enabled_profiles.append({"Name": "Domain", "Enabled": "False"})
    result = evaluate_firewall(enabled_profiles)
    assert result.status is Status.FAIL
    assert any("ambigu" in detail for detail in result.details)


@pytest.mark.parametrize("entry", [None, {}, {"Name": []}, {"Name": "Unexpected", "Enabled": "False"}])
def test_unknown_or_invalid_profile_does_not_create_false_failure(enabled_profiles, entry):
    enabled_profiles.append(entry)
    assert evaluate_firewall(enabled_profiles).status is Status.UNKNOWN


def test_missing_enabled_field_is_unknown(enabled_profiles):
    del enabled_profiles[0]["Enabled"]
    assert evaluate_firewall(enabled_profiles).status is Status.UNKNOWN
