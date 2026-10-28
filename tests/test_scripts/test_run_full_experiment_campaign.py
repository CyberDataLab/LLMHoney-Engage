import json

import pytest

import scripts.run_full_experiment_campaign as campaign_module
from scripts.run_full_experiment_campaign import (
  build_envs,
  build_session_matrix,
  group_sessions_by_model_pair,
  load_attacker_abandonment,
  make_session_id,
)


def base_config(**overrides) -> dict:
  config = {
    "models": ["model-a", "model-b"],
    "coa_modes": ["chain", "single"],
    "persona_modes": ["random", "none"],
    "attacker_levels": ["Beginner", "Advanced"],
    "repetitions": 2,
  }
  config.update(overrides)
  return config


class TestBuildSessionMatrix:
  def test_matrix_size_is_the_full_cross_product(self):
    sessions = build_session_matrix(base_config())
    assert len(sessions) == 2 * 2 * 2 * 2 * 2 * 2

  def test_includes_the_diagonal_of_same_model_pairs(self):
    sessions = build_session_matrix(base_config())
    diagonal = [s for s in sessions if s["defender_model"] == s["attacker_model"]]
    assert diagonal

  def test_includes_cross_model_pairs(self):
    sessions = build_session_matrix(base_config())
    cross = [s for s in sessions if s["defender_model"] != s["attacker_model"]]
    assert cross

  def test_missing_optional_keys_fall_back_to_defaults(self):
    sessions = build_session_matrix({"models": ["model-a"]})
    assert sessions
    assert all(s["coa_mode"] in ("chain", "single") for s in sessions)
    assert all(s["attacker_level"] in ("Beginner", "Intermediate", "Advanced") for s in sessions)


class TestGroupSessionsByModelPair:
  def test_every_session_is_assigned_to_exactly_one_pair(self):
    sessions = build_session_matrix(base_config())
    groups = group_sessions_by_model_pair(sessions)
    total_grouped = sum(len(group) for _, group in groups)
    assert total_grouped == len(sessions)

  def test_number_of_distinct_pairs_matches_model_count_squared(self):
    sessions = build_session_matrix(base_config())
    groups = group_sessions_by_model_pair(sessions)
    assert len(groups) == 2 * 2

  def test_each_group_only_contains_sessions_for_its_pair(self):
    sessions = build_session_matrix(base_config())
    groups = group_sessions_by_model_pair(sessions)
    for (defender, attacker), group in groups:
      assert all(s["defender_model"] == defender and s["attacker_model"] == attacker for s in group)

  def test_preserves_first_seen_order(self):
    sessions = build_session_matrix(base_config())
    groups = group_sessions_by_model_pair(sessions)
    seen_order = []
    for session in sessions:
      key = (session["defender_model"], session["attacker_model"])
      if key not in seen_order:
        seen_order.append(key)
    assert [pair for pair, _ in groups] == seen_order


class TestMakeSessionId:
  def test_session_id_encodes_every_matrix_dimension(self):
    plan = {
      "defender_model": "llama3.1",
      "attacker_model": "qwen2.5",
      "coa_mode": "chain",
      "persona_mode": "random",
      "attacker_level": "Advanced",
      "iteration": 2,
    }
    session_id = make_session_id(plan)
    assert "DM-llama3.1" in session_id
    assert "AM-qwen2.5" in session_id
    assert "COA-chain" in session_id
    assert "PM-random" in session_id
    assert "ALAdvanced" in session_id
    assert "_i2" in session_id

  def test_colons_and_slashes_in_model_names_are_sanitized(self):
    plan = {
      "defender_model": "qwen2:7b",
      "attacker_model": "org/model",
      "coa_mode": "chain",
      "persona_mode": "random",
      "attacker_level": "Beginner",
      "iteration": 0,
    }
    session_id = make_session_id(plan)
    assert ":" not in session_id
    assert "org/model" not in session_id

  def test_consecutive_calls_produce_distinct_ids(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Beginner", "iteration": 0,
    }
    ids = {make_session_id(plan) for _ in range(5)}
    assert len(ids) == 5


class TestBuildEnvs:
  def test_defender_and_attacker_models_are_set_correctly(self):
    plan = {
      "defender_model": "llama3.1", "attacker_model": "qwen2.5", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Beginner", "iteration": 0,
    }
    honeyengage_env, llmattacker_env = build_envs(plan, "session-1", base_config())

    assert honeyengage_env["HONEYENGAGE_CORRELATION_MODEL"] == "llama3.1"
    assert honeyengage_env["HONEYENGAGE_ENGAGE_MODEL"] == "llama3.1"
    assert llmattacker_env["LLMATTACKER_LLM_MODEL"] == "qwen2.5"

  def test_coa_and_persona_modes_are_threaded_through(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "single",
      "persona_mode": "none", "attacker_level": "Beginner", "iteration": 0,
    }
    honeyengage_env, _ = build_envs(plan, "session-1", base_config())

    assert honeyengage_env["HONEYENGAGE_COA_MODE"] == "single"
    assert honeyengage_env["HONEYENGAGE_PERSONA_MODE"] == "none"

  def test_session_id_and_seed_are_consistent_across_both_envs(self):
    plan = {
      "defender_model": "a", "attacker_model": "b", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Advanced", "iteration": 3,
    }
    honeyengage_env, llmattacker_env = build_envs(plan, "session-xyz", base_config())

    assert honeyengage_env["SESSION_ID"] == llmattacker_env["SESSION_ID"] == "session-xyz"
    assert honeyengage_env["HONEYENGAGE_SEED"] == llmattacker_env["LLMATTACKER_SEED"] == "3"

  def test_attacker_techniques_are_sampled_and_non_empty(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Advanced", "iteration": 0,
    }
    _, llmattacker_env = build_envs(plan, "session-1", base_config())

    assert llmattacker_env["LLMATTACKER_TECHNIQUES"]
    assert llmattacker_env["LLMATTACKER_TECHNIQUES"].startswith("T")

  def test_non_static_coa_modes_receive_a_bonus_pool(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Advanced", "iteration": 0,
    }
    _, llmattacker_env = build_envs(plan, "session-1", base_config())

    assert llmattacker_env["LLMATTACKER_BONUS_TECHNIQUES"]
    assert llmattacker_env["LLMATTACKER_BONUS_TECHNIQUES"].startswith("T")

  def test_static_coa_mode_receives_no_bonus_pool(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "static",
      "persona_mode": "random", "attacker_level": "Advanced", "iteration": 0,
    }
    _, llmattacker_env = build_envs(plan, "session-1", base_config())

    assert llmattacker_env["LLMATTACKER_BONUS_TECHNIQUES"] == ""

  def test_bonus_techniques_never_overlap_the_base_pool(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Advanced", "iteration": 0,
    }
    _, llmattacker_env = build_envs(plan, "session-1", base_config())

    base = set(llmattacker_env["LLMATTACKER_TECHNIQUES"].split(","))
    bonus = set(llmattacker_env["LLMATTACKER_BONUS_TECHNIQUES"].split(","))
    assert not (base & bonus)

  def test_ollama_base_url_defaults_when_absent_from_config(self):
    plan = {
      "defender_model": "a", "attacker_model": "a", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Beginner", "iteration": 0,
    }
    honeyengage_env, llmattacker_env = build_envs(plan, "session-1", {})

    assert honeyengage_env["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
    assert llmattacker_env["OPENAI_BASE_URL"] == "http://localhost:11434/v1"

  def test_profile_seed_key_is_stable_across_coa_modes(self):
    base = {
      "defender_model": "a", "attacker_model": "qwen2.5",
      "persona_mode": "random", "attacker_level": "Advanced", "iteration": 1,
    }
    _, llmattacker_env_chain = build_envs({**base, "coa_mode": "chain"}, "session-chain", {})
    _, llmattacker_env_static = build_envs({**base, "coa_mode": "static"}, "session-static", {})

    assert llmattacker_env_chain["LLMATTACKER_PROFILE_SEED_KEY"] == llmattacker_env_static["LLMATTACKER_PROFILE_SEED_KEY"]
    assert "chain" not in llmattacker_env_chain["LLMATTACKER_PROFILE_SEED_KEY"]
    assert "static" not in llmattacker_env_chain["LLMATTACKER_PROFILE_SEED_KEY"]

  def test_profile_seed_key_varies_with_attacker_level(self):
    base = {
      "defender_model": "a", "attacker_model": "qwen2.5", "coa_mode": "chain",
      "persona_mode": "random", "iteration": 0,
    }
    _, env_beginner = build_envs({**base, "attacker_level": "Beginner"}, "session-1", {})
    _, env_advanced = build_envs({**base, "attacker_level": "Advanced"}, "session-2", {})

    assert env_beginner["LLMATTACKER_PROFILE_SEED_KEY"] != env_advanced["LLMATTACKER_PROFILE_SEED_KEY"]

  def test_judge_model_is_pinned_independently_of_the_attacker_model(self):
    plan = {
      "defender_model": "a", "attacker_model": "qwen2.5", "coa_mode": "chain",
      "persona_mode": "random", "attacker_level": "Beginner", "iteration": 0,
    }
    _, llmattacker_env = build_envs(plan, "session-1", {"judge_model": "llama3.1"})

    assert llmattacker_env["LLMATTACKER_LLM_MODEL"] == "qwen2.5"
    assert llmattacker_env["LLMATTACKER_JUDGE_MODEL"] == "llama3.1"


class TestLoadAttackerAbandonment:
  def test_returns_none_defaults_when_metrics_file_is_absent(self, tmp_path, monkeypatch):
    monkeypatch.setattr(campaign_module, "LLMATTACKER_METRICS_FILE", tmp_path / "does_not_exist.jsonl")
    result = load_attacker_abandonment("session-1")
    assert result == {
      "detected_honeypot": None, "abandoned_as_honeypot": None,
      "abandoned_as_uninteresting": None, "techniques_attempted_before_abandoning": None,
      "assigned_pool_size": None, "assigned_pool_exhausted": None, "bonus_techniques_used": None,
    }

  def test_finds_the_matching_session_by_id(self, tmp_path, monkeypatch):
    metrics_file = tmp_path / "attack_metrics.jsonl"
    metrics_file.write_text(
      json.dumps({"session_id": "session-A", "event_type": "attack_simulation", "detected_honeypot": False, "abandoned_as_honeypot": False, "abandoned_as_uninteresting": False, "techniques_attempted_before_abandoning": None}) + "\n"
      + json.dumps({"session_id": "session-B", "event_type": "attack_simulation", "detected_honeypot": True, "abandoned_as_honeypot": True, "abandoned_as_uninteresting": False, "techniques_attempted_before_abandoning": 2}) + "\n"
    )
    monkeypatch.setattr(campaign_module, "LLMATTACKER_METRICS_FILE", metrics_file)

    result = load_attacker_abandonment("session-B")

    assert result == {
      "detected_honeypot": True, "abandoned_as_honeypot": True,
      "abandoned_as_uninteresting": False, "techniques_attempted_before_abandoning": 2,
      "assigned_pool_size": None, "assigned_pool_exhausted": None, "bonus_techniques_used": None,
    }

  def test_ignores_command_level_events_and_reads_only_the_session_summary(self, tmp_path, monkeypatch):
    metrics_file = tmp_path / "attack_metrics.jsonl"
    metrics_file.write_text(
      json.dumps({"session_id": "session-A", "event_type": "command", "abandoned_as_honeypot": "should-not-be-read"}) + "\n"
      + json.dumps({"session_id": "session-A", "event_type": "attack_simulation", "abandoned_as_honeypot": True, "detected_honeypot": True, "techniques_attempted_before_abandoning": 1}) + "\n"
    )
    monkeypatch.setattr(campaign_module, "LLMATTACKER_METRICS_FILE", metrics_file)

    result = load_attacker_abandonment("session-A")

    assert result["abandoned_as_honeypot"] is True


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
