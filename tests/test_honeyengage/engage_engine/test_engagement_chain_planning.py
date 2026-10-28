import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import src.honeyengage.engage_engine.engage_engine as engage_engine_module
from src.honeyengage.engage_engine.engage_mapping import (
  EngageActivity,
  EngageApproach,
  EngageDetails,
  EngageGoal,
  EngageVulnerability,
)
from src.honeyengage.engage_engine.scenario_catalog import ScenarioTemplate


class DummyParser:
  def __init__(self, *args, **kwargs):
    self.mapper = {}


class RecordingCapability:
  execution_log: list[str] = []
  required_fields: dict[str, str] = {}

  def __init__(self, vfs, virtual_shell, eac_id, options):
    self.eac_id = eac_id
    self.options = options

  @classmethod
  def option_fields(cls):
    return cls.required_fields

  def execute(self):
    RecordingCapability.execution_log.append(type(self).__name__)
    return SimpleNamespace(success=True, eac_id=self.eac_id, message="ok")


class CreateFakeUserAccountCapability(RecordingCapability):
  pass


class ModifyBashHistoryCapability(RecordingCapability):
  pass


class CreateLogFileCapability(RecordingCapability):
  pass


class InjectFakeNetworkConnectionCapability(RecordingCapability):
  pass


CAPABILITY_CLASSES = {
  "CreateFakeUserAccountCapability": CreateFakeUserAccountCapability,
  "ModifyBashHistoryCapability": ModifyBashHistoryCapability,
  "CreateLogFileCapability": CreateLogFileCapability,
  "InjectFakeNetworkConnectionCapability": InjectFakeNetworkConnectionCapability,
}

FULL_CHAIN_SCENARIO = ScenarioTemplate(
  scenario_id="test_full_chain",
  eac_id="EAC0005",
  narrative="Fake account, matching bash history, and a log entry",
  capability_chain=["CreateFakeUserAccountCapability", "ModifyBashHistoryCapability", "CreateLogFileCapability"],
)
TWO_STEP_SCENARIO = ScenarioTemplate(
  scenario_id="test_two_step",
  eac_id="EAC0005",
  narrative="Fake account with matching bash history",
  capability_chain=["CreateFakeUserAccountCapability", "ModifyBashHistoryCapability"],
)
FOUR_STEP_SCENARIO = ScenarioTemplate(
  scenario_id="test_four_step",
  eac_id="EAC0005",
  narrative="Full identity bait with an active-looking connection",
  capability_chain=[
    "CreateFakeUserAccountCapability", "ModifyBashHistoryCapability",
    "CreateLogFileCapability", "InjectFakeNetworkConnectionCapability",
  ],
)
UNSUPPORTED_STEP_SCENARIO = ScenarioTemplate(
  scenario_id="test_unsupported_step",
  eac_id="EAC0005",
  narrative="A scenario whose chain references a capability that isn't registered",
  capability_chain=["CreateFakeUserAccountCapability", "NotRealCapability"],
)

DEFAULT_CANDIDATES = [FULL_CHAIN_SCENARIO, TWO_STEP_SCENARIO, FOUR_STEP_SCENARIO]


VALID_CHAIN_RESPONSE = json.dumps({name: {} for name in CAPABILITY_CLASSES})


def make_llm_client(planning_response, options_response='{}', chain_response=VALID_CHAIN_RESPONSE):
  client = MagicMock()

  def fake_create(**kwargs):
    system_content = kwargs["messages"][0]["content"]
    user_content = kwargs["messages"][1]["content"]
    if "scenario_id" in system_content:
      content = planning_response
    elif "MUST TELL TOGETHER" in user_content:
      content = chain_response
    else:
      content = options_response
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

  client.chat.completions.create.side_effect = fake_create
  return client


def build_engine(monkeypatch, planning_response, options_response='{}', candidates=None,
                 chain_response=VALID_CHAIN_RESPONSE):
  monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)
  monkeypatch.setattr(
    engage_engine_module.EngageEngine, "discover_capabilities", lambda self, pkg: dict(CAPABILITY_CLASSES)
  )
  monkeypatch.setattr(
    engage_engine_module, "scenarios_for_activity", lambda eac_id, role_id=None: list(candidates or DEFAULT_CANDIDATES)
  )
  RecordingCapability.execution_log = []

  client = make_llm_client(planning_response, options_response, chain_response)
  engine = engage_engine_module.EngageEngine(client)
  vfs = MagicMock()
  virtual_shell = MagicMock()
  virtual_shell.persona.role_id = "workstation"
  virtual_shell.persona.display_name = "Developer workstation"
  return engine, vfs, virtual_shell


def lures_engage_details() -> EngageDetails:
  return EngageDetails(
    goal=EngageGoal(goal_id="EAG0001", name="Goal", short_description="", long_description=""),
    approach=EngageApproach(approach_id="EAP0001", name="Approach", short_description="", long_description=""),
    activity=EngageActivity(activity_id="EAC0005", name="Lures", short_description="", long_description=""),
    vulnerability=EngageVulnerability(vulnerability_id="EV0001", description=""),
  )


class TestEngagementChainPlanning:
  def test_executes_every_planned_step_in_order(self, monkeypatch):
    plan = json.dumps({
      "scenario_id": "test_full_chain",
      "reasoning": "Build a coherent fake persona with matching history and logs.",
    })
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    result = engine.evaluate_and_react(
      "session-1", "cat /etc/passwd", "OS Credential Dumping", [lures_engage_details()], vfs, virtual_shell
    )

    scenario_chain = ["CreateFakeUserAccountCapability", "ModifyBashHistoryCapability", "CreateLogFileCapability"]
    assert [step.capability_name for step in result.steps][:len(scenario_chain)] == scenario_chain
    assert RecordingCapability.execution_log[:len(scenario_chain)] == scenario_chain

  def test_chain_result_status_is_success_when_every_step_succeeds(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_two_step"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert result.result_status == "success"

  def test_scenario_with_unregistered_capability_skips_that_step(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_unsupported_step"})
    engine, vfs, virtual_shell = build_engine(
      monkeypatch, plan, candidates=[UNSUPPORTED_STEP_SCENARIO, TWO_STEP_SCENARIO]
    )

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    statuses = {step.capability_name: step.result_status for step in result.steps}
    assert statuses["CreateFakeUserAccountCapability"] == "success"
    assert statuses["NotRealCapability"] == "unsupported_capability"

  def test_four_step_scenario_runs_all_four_steps(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_four_step"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert len(result.steps) == 4

  def test_falls_back_to_random_scenario_when_llm_returns_invalid_json(self, monkeypatch):
    engine, vfs, virtual_shell = build_engine(monkeypatch, planning_response="not json at all")

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    executed = {step.capability_name for step in result.steps}
    assert executed.issubset(set(CAPABILITY_CLASSES))
    assert len(result.steps) >= 1

  def test_unreachable_llm_deploys_no_partial_story(self, monkeypatch):
    engine, vfs, virtual_shell = build_engine(monkeypatch, planning_response="{}")
    engine.llm_client.chat.completions.create.side_effect = RuntimeError("connection refused")

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert result.result_status == "failure"
    assert result.steps == []
    assert RecordingCapability.execution_log == []

  def test_chain_is_regenerated_whole_until_valid(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_full_chain"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)
    valid = engine.llm_client.chat.completions.create.side_effect
    calls = {"chain": 0}

    def flaky(**kwargs):
      if "MUST TELL TOGETHER" in kwargs["messages"][1]["content"]:
        calls["chain"] += 1
        if calls["chain"] == 1:
          return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))])
      return valid(**kwargs)

    engine.llm_client.chat.completions.create.side_effect = flaky
    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert calls["chain"] == 2
    assert result.result_status == "success"
    assert RecordingCapability.execution_log[:3] == FULL_CHAIN_SCENARIO.capability_chain

  def test_chain_never_valid_deploys_nothing(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_full_chain"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan, chain_response="{}")

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert result.steps == []
    assert RecordingCapability.execution_log == []

  def test_falls_back_to_random_scenario_when_scenario_id_is_unknown(self, monkeypatch):
    plan = json.dumps({"scenario_id": "does_not_exist"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    executed = {step.capability_name for step in result.steps}
    assert executed.issubset(set(CAPABILITY_CLASSES))
    assert len(result.steps) >= 1

  def test_uses_single_candidate_directly_without_calling_llm(self, monkeypatch):
    engine, vfs, virtual_shell = build_engine(monkeypatch, planning_response="{}", candidates=[TWO_STEP_SCENARIO])

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert [step.capability_name for step in result.steps][:2] == [
      "CreateFakeUserAccountCapability", "ModifyBashHistoryCapability",
    ]
    planning_calls = [
      call for call in engine.llm_client.chat.completions.create.call_args_list
      if "scenario_id" in call.kwargs["messages"][0]["content"]
    ]
    assert planning_calls == []

  def test_falls_back_to_single_capability_without_llm_client(self, monkeypatch):
    monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)
    monkeypatch.setattr(
      engage_engine_module.EngageEngine, "discover_capabilities", lambda self, pkg: dict(CAPABILITY_CLASSES)
    )
    monkeypatch.setattr(
      engage_engine_module, "scenarios_for_activity", lambda eac_id, role_id=None: list(DEFAULT_CANDIDATES)
    )
    engine = engage_engine_module.EngageEngine(llm_client=None)
    vfs, virtual_shell = MagicMock(), MagicMock()
    virtual_shell.persona.role_id = "workstation"

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert len(result.steps) >= 1

  def test_no_scenarios_for_activity_falls_back_to_single_capability(self, monkeypatch):
    monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)
    monkeypatch.setattr(
      engage_engine_module.EngageEngine, "discover_capabilities", lambda self, pkg: dict(CAPABILITY_CLASSES)
    )
    monkeypatch.setattr(engage_engine_module, "scenarios_for_activity", lambda eac_id, role_id=None: [])
    engine = engage_engine_module.EngageEngine(llm_client=MagicMock())
    vfs, virtual_shell = MagicMock(), MagicMock()
    virtual_shell.persona.role_id = "workstation"

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert len(result.steps) == 1

  def test_no_valid_capabilities_for_activity_returns_unsupported_without_crashing(self, monkeypatch):
    monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)
    monkeypatch.setattr(engage_engine_module.EngageEngine, "discover_capabilities", lambda self, pkg: {})
    engine = engage_engine_module.EngageEngine(llm_client=MagicMock())
    vfs, virtual_shell = MagicMock(), MagicMock()
    virtual_shell.persona.role_id = "workstation"

    unmapped_activity = EngageDetails(
      goal=EngageGoal(goal_id="EAG0099", name="Goal", short_description="", long_description=""),
      approach=EngageApproach(approach_id="EAP0099", name="Approach", short_description="", long_description=""),
      activity=EngageActivity(activity_id="EAC9999", name="Unmapped", short_description="", long_description=""),
      vulnerability=EngageVulnerability(vulnerability_id="EV0099", description=""),
    )

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [unmapped_activity], vfs, virtual_shell)

    assert result.result_status == "unsupported_capability"
    assert result.steps == []

  def test_previously_used_capabilities_are_included_in_the_planning_prompt(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_two_step"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    engine.evaluate_and_react(
      "session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell,
      previously_used_capabilities=["CreateLogFileCapability", "CreateLogFileCapability"],
    )

    planning_call = next(
      call for call in engine.llm_client.chat.completions.create.call_args_list
      if "scenario_id" in call.kwargs["messages"][0]["content"]
    )
    user_prompt = planning_call.kwargs["messages"][1]["content"]
    assert "CreateLogFileCapability" in user_prompt

  def test_machine_persona_is_included_in_the_planning_prompt(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_two_step"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    planning_call = next(
      call for call in engine.llm_client.chat.completions.create.call_args_list
      if "scenario_id" in call.kwargs["messages"][0]["content"]
    )
    user_prompt = planning_call.kwargs["messages"][1]["content"]
    assert "Developer workstation" in user_prompt

  def test_coa_mode_single_bypasses_scenario_planning_entirely(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_COA_MODE", "single")
    plan = json.dumps({"scenario_id": "test_full_chain"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert len(result.steps) == 1
    planning_calls = [
      call for call in engine.llm_client.chat.completions.create.call_args_list
      if "scenario_id" in call.kwargs["messages"][0]["content"]
    ]
    assert planning_calls == []

  def test_coa_mode_multi_ttp_bypasses_scenario_planning_entirely(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_COA_MODE", "multi_ttp")
    plan = json.dumps({"scenario_id": "test_full_chain"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert 1 <= len(result.steps) <= 4
    planning_calls = [
      call for call in engine.llm_client.chat.completions.create.call_args_list
      if "scenario_id" in call.kwargs["messages"][0]["content"]
    ]
    assert planning_calls == []

  def test_coa_mode_multi_ttp_draws_across_multiple_activities(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_COA_MODE", "multi_ttp")
    plan = json.dumps({"scenario_id": "test_full_chain"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    system_activity_monitoring = EngageDetails(
      goal=EngageGoal(goal_id="EAG0001", name="Goal", short_description="", long_description=""),
      approach=EngageApproach(approach_id="EAP0001", name="Approach", short_description="", long_description=""),
      activity=EngageActivity(activity_id="EAC0003", name="System Activity Monitoring", short_description="", long_description=""),
      vulnerability=EngageVulnerability(vulnerability_id="EV0001", description=""),
    )

    seen_multi_activity = False
    for seed_session in [f"session-{i}" for i in range(30)]:
      result = engine.evaluate_and_react(
        seed_session, "cmd", "desc", [lures_engage_details(), system_activity_monitoring], vfs, virtual_shell,
      )
      activities_used = {step.eac_id for step in result.steps}
      if len(activities_used) > 1:
        seen_multi_activity = True
        break

    assert seen_multi_activity, "multi_ttp never mixed capabilities across activities over 30 sessions"

  def test_coa_mode_same_ttp_stays_on_one_activity_across_a_whole_session(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_COA_MODE", "same_ttp")
    plan = json.dumps({"scenario_id": "test_full_chain"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    system_activity_monitoring = EngageDetails(
      goal=EngageGoal(goal_id="EAG0001", name="Goal", short_description="", long_description=""),
      approach=EngageApproach(approach_id="EAP0001", name="Approach", short_description="", long_description=""),
      activity=EngageActivity(activity_id="EAC0003", name="System Activity Monitoring", short_description="", long_description=""),
      vulnerability=EngageVulnerability(vulnerability_id="EV0001", description=""),
    )

    activities_seen: set[str] = set()
    for _ in range(10):
      result = engine.evaluate_and_react(
        "session-same-ttp", "cmd", "desc",
        [lures_engage_details(), system_activity_monitoring], vfs, virtual_shell,
      )
      activities_seen.update(step.eac_id for step in result.steps)

    assert len(activities_seen) == 1, (
      f"same_ttp must stay confined to a single Engage activity for the whole "
      f"session, but deployed capabilities from {sorted(activities_seen)}"
    )

  def test_coa_mode_defaults_to_chain(self, monkeypatch):
    monkeypatch.delenv("HONEYENGAGE_COA_MODE", raising=False)
    monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)
    monkeypatch.setattr(
      engage_engine_module.EngageEngine, "discover_capabilities", lambda self, pkg: dict(CAPABILITY_CLASSES)
    )
    engine = engage_engine_module.EngageEngine(llm_client=MagicMock())
    assert engine.coa_mode == "chain"

  def test_summary_reflects_first_failure_not_last_step(self, monkeypatch):
    plan = json.dumps({"scenario_id": "test_two_step"})
    engine, vfs, virtual_shell = build_engine(monkeypatch, plan)

    def failing_execute(self):
      return SimpleNamespace(success=False, eac_id=self.eac_id, message="simulated failure")

    monkeypatch.setattr(CreateFakeUserAccountCapability, "execute", failing_execute)

    result = engine.evaluate_and_react("session-1", "cmd", "desc", [lures_engage_details()], vfs, virtual_shell)

    assert result.result_status != "success"
    assert result.capability_name == "CreateFakeUserAccountCapability"


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
