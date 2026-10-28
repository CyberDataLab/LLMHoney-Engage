from unittest.mock import MagicMock

from src.honeyengage.engage_engine.engage_engine import EngageEngine
from src.honeyengage.engage_engine.scenario_catalog import SCENARIO_CATALOG, scenarios_for_activity


class TestScenarioCatalogIntegrity:
  def test_every_referenced_capability_is_actually_registered(self):
    engine = EngageEngine(llm_client=MagicMock())
    known_capabilities = set(engine.capabilities_registry.keys())

    referenced = {name for scenario in SCENARIO_CATALOG for name in scenario.capability_chain}
    unknown = referenced - known_capabilities

    assert not unknown, f"Scenario catalog references unknown capabilities: {unknown}"

  def test_every_scenario_has_a_non_empty_capability_chain(self):
    assert all(len(scenario.capability_chain) >= 1 for scenario in SCENARIO_CATALOG)

  def test_scenario_ids_are_unique(self):
    ids = [scenario.scenario_id for scenario in SCENARIO_CATALOG]
    assert len(ids) == len(set(ids))


class TestScenariosForActivity:
  def test_returns_only_scenarios_for_the_requested_activity(self):
    scenarios = scenarios_for_activity("EAC0005")
    assert scenarios
    assert all(s.eac_id == "EAC0005" for s in scenarios)

  def test_unknown_activity_returns_empty_list(self):
    assert scenarios_for_activity("EAC9999") == []

  def test_role_filter_excludes_incompatible_scenarios(self):
    all_scenarios = scenarios_for_activity("EAC0006")
    web_scenarios = scenarios_for_activity("EAC0006", role_id="web_server")
    mail_scenarios = scenarios_for_activity("EAC0006", role_id="mail_relay")

    assert len(web_scenarios) <= len(all_scenarios)
    assert {s.scenario_id for s in web_scenarios} != {s.scenario_id for s in mail_scenarios} or not web_scenarios

  def test_scenario_with_no_compatible_roles_fits_any_role(self):
    scenarios = scenarios_for_activity("EAC0005", role_id="some_made_up_role")
    assert scenarios


class TestFitsRole:
  def test_empty_compatible_roles_fits_everything(self):
    scenario = scenarios_for_activity("EAC0005")[0]
    if not scenario.compatible_roles:
      assert scenario.fits_role("anything")

  def test_restricted_scenario_only_fits_listed_roles(self):
    email_scenario = scenarios_for_activity("EAC0009")[0]
    assert email_scenario.fits_role("mail_relay")
    assert not email_scenario.fits_role("workstation")
