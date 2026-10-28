import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.llmattacker.threat_actor.attack_planner import AttackPlanner, TechniqueOutcome
from src.llmattacker.threat_actor.profile import THREAT_ACTOR_PROFILES


def make_llm_response(content):
  return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def make_llm_client(response_content):
  client = MagicMock()
  client.chat.completions.create.return_value = make_llm_response(response_content)
  return client


class TestDecideNextStep:
  def test_no_remaining_techniques_stops_without_calling_llm(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    client = make_llm_client("{}")
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step([], [])

    assert decision.next_technique_id is None
    client.chat.completions.create.assert_not_called()

  def test_no_llm_client_falls_back_to_fixed_order(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    planner = AttackPlanner(llm_client=None, profile=THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step(["T1033", "T1082"], [])

    assert decision.next_technique_id == "T1033"

  def test_valid_llm_choice_is_honored(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1082", "reasoning": "prioritizing discovery"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["nation_state_spy"])

    decision = planner.decide_next_step(["T1033", "T1082"], [])

    assert decision.next_technique_id == "T1082"
    assert decision.reasoning == "prioritizing discovery"

  def test_llm_can_choose_to_stop(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": None, "reasoning": "too risky, bailing out"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step(["T1033", "T1082"], [])

    assert decision.next_technique_id is None
    assert "bailing out" in decision.reasoning

  def test_llm_choosing_a_technique_outside_the_remaining_list_falls_back(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T9999", "reasoning": "hallucinated"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step(["T1033", "T1082"], [])

    assert decision.next_technique_id == "T1033"

  def test_invalid_json_falls_back_to_fixed_order(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    client = make_llm_client("not json at all")
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step(["T1033", "T1082"], [])

    assert decision.next_technique_id == "T1033"

  def test_llm_call_raising_falls_back_to_fixed_order(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    client = MagicMock()
    client.chat.completions.create.side_effect = RuntimeError("connection refused")
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step(["T1033", "T1082"], [])

    assert decision.next_technique_id == "T1033"

  def test_history_is_included_in_the_planning_prompt(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1082"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["nation_state_spy"])

    history = [TechniqueOutcome(technique_id="T1033", commands_executed=2, honeypot_detected=True, avg_credibility=0.2)]
    planner.decide_next_step(["T1082"], history)

    user_prompt = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
    assert "T1033" in user_prompt
    assert "HONEYPOT SUSPECTED" in user_prompt

  def test_system_prompt_never_tells_the_planner_to_stop_on_suspicion(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1033"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    planner.decide_next_step(["T1033"], [])

    system_prompt = client.chat.completions.create.call_args.kwargs["messages"][0]["content"]
    assert "abandons the session quickly once something looks off" not in system_prompt
    assert "last attempt looked like a honeypot" not in system_prompt

  def test_profile_attributes_are_included_in_the_planning_prompt(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1033"})
    client = make_llm_client(plan)
    profile = THREAT_ACTOR_PROFILES["ransomware_operator"]
    planner = AttackPlanner(client, profile)

    planner.decide_next_step(["T1033"], [])

    user_prompt = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
    assert profile.motivation in user_prompt
    assert profile.attitude in user_prompt

  def test_session_level_credibility_summary_is_included_in_the_prompt(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1082"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["nation_state_spy"])

    history = [
      TechniqueOutcome(technique_id="T1033", commands_executed=4, honeypot_detected=False, avg_credibility=0.9),
      TechniqueOutcome(technique_id="T1057", commands_executed=6, honeypot_detected=False, avg_credibility=0.8),
    ]
    planner.decide_next_step(["T1082"], history)

    user_prompt = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
    assert "Session so far (overall)" in user_prompt
    assert "Commands run: 10" in user_prompt
    assert "Session-wide avg_credibility: 0.85" in user_prompt
    assert "suspicious: 0/2" in user_prompt

  def test_high_credibility_is_framed_as_a_reason_to_continue(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1033"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    planner.decide_next_step(["T1033"], [])

    system_prompt = client.chat.completions.create.call_args.kwargs["messages"][0]["content"]
    assert "worth the effort" in system_prompt
    assert "keep working it" in system_prompt

  def test_no_remaining_but_bonus_available_still_calls_llm(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": None, "reasoning": "convincing so far, going deeper", "request_bonus_technique": True})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["nation_state_spy"])

    decision = planner.decide_next_step([], [], bonus_available=True)

    client.chat.completions.create.assert_called_once()
    assert decision.next_technique_id is None
    assert decision.request_bonus_technique is True

  def test_bonus_request_ignored_when_bonus_not_available(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": None, "reasoning": "stopping", "request_bonus_technique": True})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    decision = planner.decide_next_step(["T1033"], [], bonus_available=False)

    assert decision.request_bonus_technique is False

  def test_bonus_instructions_only_appear_in_prompt_when_available(self, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "test-model")
    plan = json.dumps({"next_technique_id": "T1033"})
    client = make_llm_client(plan)
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])

    planner.decide_next_step(["T1033"], [], bonus_available=True)
    system_prompt_with_bonus = client.chat.completions.create.call_args.kwargs["messages"][0]["content"]

    client.chat.completions.create.reset_mock()
    planner.decide_next_step(["T1033"], [], bonus_available=False)
    system_prompt_without_bonus = client.chat.completions.create.call_args.kwargs["messages"][0]["content"]

    assert "Set \"request_bonus_technique\": true" in system_prompt_with_bonus
    assert "Set \"request_bonus_technique\": true" not in system_prompt_without_bonus

  def test_missing_llm_model_falls_back_without_calling_llm(self, monkeypatch):
    monkeypatch.delenv("LLMATTACKER_LLM_MODEL", raising=False)
    client = make_llm_client("{}")
    planner = AttackPlanner(client, THREAT_ACTOR_PROFILES["script_kiddie"])
    planner.llm_model = ""

    decision = planner.decide_next_step(["T1033"], [])

    assert decision.next_technique_id == "T1033"
    client.chat.completions.create.assert_not_called()


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
