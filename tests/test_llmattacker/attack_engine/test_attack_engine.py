import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.llmattacker.attack_engine.attack_engine import AttackEngine
from src.llmattacker.deception_engine.credibility_analyzer import EvaluationResult
from src.llmattacker.threat_actor.attack_planner import TechniqueOutcome
from src.llmattacker.threat_actor.profile import THREAT_ACTOR_PROFILES

LINUX_ONLY_TECHNIQUE_YAML = """
attack_technique: T9001
display_name: Fake Discovery Technique
atomic_tests:
- name: Linux discovery test
  supported_platforms:
  - linux
  executor:
    command: |
      whoami
      id
"""

MIXED_PLATFORM_TECHNIQUE_YAML = """
attack_technique: T9002
display_name: Mixed Platform Technique
atomic_tests:
- name: Windows-only test
  supported_platforms:
  - windows
  executor:
    command: |
      wmic useraccount get /ALL
- name: Linux test
  supported_platforms:
  - linux
  executor:
    command: |
      whoami
"""

TECHNIQUE_WITH_ARGS_AND_CLEANUP_YAML = """
attack_technique: T9003
display_name: Technique With Args
atomic_tests:
- name: Test with placeholder args
  supported_platforms:
  - linux
  input_arguments:
    target_file:
      description: File to touch
      type: path
      default: /tmp/decoy.txt
  executor:
    command: |
      touch #{target_file}
    cleanup_command: |
      rm -f #{target_file}
"""

NO_SUPPORTED_PLATFORMS_KEY_YAML = """
attack_technique: T9004
display_name: Technique Without Platform Restriction
atomic_tests:
- name: Test without supported_platforms key
  executor:
    command: |
      pwd
"""


def write_technique(atomics_dir, technique_id, yaml_content):
  technique_dir = atomics_dir / technique_id
  technique_dir.mkdir(parents=True, exist_ok=True)
  (technique_dir / f"{technique_id}.yaml").write_text(yaml_content)


@pytest.fixture
def mock_interactor():
  interactor = MagicMock()
  interactor.connect.return_value = True
  interactor.execute_command.return_value = "some output"
  return interactor


@pytest.fixture
def metrics_file(tmp_path):
  return str(tmp_path / "attack_metrics.jsonl")


def build_engine(atomics_path, interactor, metrics_file, monkeypatch, **env):
  monkeypatch.delenv("ORACLE_HOST", raising=False)
  for key, value in env.items():
    monkeypatch.setenv(key, value)

  with patch("src.llmattacker.attack_engine.attack_engine.CredibilityAnalyzer") as mock_analyzer_cls, \
       patch("src.llmattacker.attack_engine.attack_engine.OpenAI") as mock_openai_cls:
    mock_analyzer = MagicMock()
    mock_analyzer.threshold = 0.5
    mock_analyzer.model = "test-model"
    mock_analyzer.analyze_response.return_value = EvaluationResult("credible", 1.0)
    mock_analyzer_cls.return_value = mock_analyzer

    mock_openai_cls.return_value.chat.completions.create.side_effect = RuntimeError("no LLM in tests")

    engine = AttackEngine(
      atomics_path=str(atomics_path),
      interactor=interactor,
      enable_metrics=True,
      metrics_file=metrics_file,
    )
  return engine


class TestAttackEngineInit:
  def test_init_reads_techniques_from_env(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_TECHNIQUES="T1033,T1082")

    assert engine.techniques == ["T1033", "T1082"]

  def test_init_defaults_to_no_techniques(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    monkeypatch.delenv("LLMATTACKER_TECHNIQUES", raising=False)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    assert engine.techniques == []

  def test_profile_seed_key_overrides_session_id_when_present(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine_a = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      SESSION_ID="campaign-x_COA-chain_ALAdvanced", LLMATTACKER_PROFILE_SEED_KEY="AM-x_ALAdvanced_i0", LLMATTACKER_SEED="42",
    )
    engine_b = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      SESSION_ID="campaign-y_COA-static_ALAdvanced", LLMATTACKER_PROFILE_SEED_KEY="AM-x_ALAdvanced_i0", LLMATTACKER_SEED="42",
    )

    assert engine_a.profile.profile_id == engine_b.profile.profile_id

  def test_init_without_oracle_host_disables_oracle(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    assert engine.oracle_client is None

  def test_init_with_unreachable_oracle_host_disables_oracle_gracefully(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    monkeypatch.setenv("ORACLE_HOST", "10.255.255.1")
    with patch("src.llmattacker.attack_engine.attack_engine.paramiko.SSHClient") as mock_ssh_cls:
      mock_ssh_cls.return_value.connect.side_effect = TimeoutError("no route to host")
      with patch("src.llmattacker.attack_engine.attack_engine.CredibilityAnalyzer") as mock_analyzer_cls:
        mock_analyzer_cls.return_value = MagicMock(threshold=0.5, model="test-model")
        engine = AttackEngine(
          atomics_path=str(tmp_path),
          interactor=mock_interactor,
          enable_metrics=False,
        )

    assert engine.oracle_client is None


class TestIsLinuxSupported:
  def test_supports_test_with_no_platform_restriction(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)
    assert engine._is_linux_supported({}) is True

  def test_supports_test_declaring_linux(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)
    assert engine._is_linux_supported({"supported_platforms": ["linux"]}) is True

  def test_rejects_test_declaring_only_windows(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)
    assert engine._is_linux_supported({"supported_platforms": ["windows"]}) is False

  def test_is_case_insensitive(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)
    assert engine._is_linux_supported({"supported_platforms": ["Linux"]}) is True


class TestAddArgumentsToCommands:
  def test_replaces_placeholder_with_default_value(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    result = engine.add_arguments_to_commands(
      "touch #{target_file}", {"target_file": {"default": "/tmp/decoy.txt"}}
    )

    assert result == "touch /tmp/decoy.txt"

  def test_leaves_command_unchanged_without_matching_placeholder(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    result = engine.add_arguments_to_commands("whoami", {})

    assert result == "whoami"


class TestNotableTokenFiltering:

  def test_systemd_durations_and_timestamp_fragments_are_not_novel(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    output = "systemctl\nActiveState=active 45s 23m 1m0s 15s 1m32.45s 2023-02-16t14 2022-09-01t14 00z"
    tokens = engine._extract_notable_tokens(output, "systemctl")

    for noise in {"45s", "23m", "1m0s", "15s", "1m32.45s", "2023-02-16t14", "2022-09-01t14", "00z"}:
      assert noise not in tokens, f"{noise!r} is output formatting, not a discovery about the target"

  def test_ping_statistics_footer_is_not_novel(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    output = (
      "ping -c 2 8.8.8.8\n"
      "2 packets transmitted, 2 received, 0% packet loss\n"
      "rtt min/avg/max/mdev = 50.352/52.441/2.100 ms"
    )
    tokens = engine._extract_notable_tokens(output, "ping -c 2 8.8.8.8")

    for noise in {"statistics", "transmitted", "packets", "packet", "loss", "min", "avg", "max", "mdev"}:
      assert noise not in tokens, f"{noise!r} is ping's fixed footer, not target content"

  def test_generic_status_words_do_not_earn_an_artifact_class(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    for word in ["failed", "port", "connection", "refused", "connect", "active", "running", "config", "status"]:
      assert engine._classify_artifact_tokens({word}) == {"other"}, (
        f"{word!r} is shell boilerplate, not a discovery about the target"
      )

  def test_real_artifacts_still_earn_their_class(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    expected = {
      "/var/log/nginx-access.log": "log",
      "/var/backups/db.sql.gz": "backup",
      "id_rsa": "credential",
      "/home/daniel": "account",
      ".bash_history": "history",
      "/tmp/staging": "tempfile",
      "redis.conf": "config",
    }
    for token, klass in expected.items():
      assert klass in engine._classify_artifact_tokens({token}), f"{token!r} should classify as {klass}"

  def test_real_target_content_still_counts_as_novel(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    output = "ls /var/log/\n/var/log/backup-vault.log\nprod-db-credentials.txt"
    tokens = engine._extract_notable_tokens(output, "ls /var/log/")

    assert "/var/log/backup-vault.log" in tokens
    assert "prod-db-credentials.txt" in tokens


class TestExecuteTechnique:
  def test_missing_yaml_file_returns_no_detection_no_commands(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch)

    detected, commands_run, scores, notable_tokens, result_text = engine.execute_technique("session-1", "T0000")

    assert detected is False
    assert commands_run == 0
    assert scores == []
    assert notable_tokens == set()

  def test_executes_linux_supported_commands(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="false")

    detected, commands_run, scores, notable_tokens, result_text = engine.execute_technique("session-1", "T9001")

    assert commands_run == 2
    assert scores == [1.0, 1.0]
    assert detected is False
    assert mock_interactor.execute_command.call_count == 2
    mock_interactor.execute_command.assert_any_call("whoami")
    mock_interactor.execute_command.assert_any_call("id")

  def test_skips_windows_only_tests_and_runs_linux_test(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9002", MIXED_PLATFORM_TECHNIQUE_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="false")

    detected, commands_run, scores, notable_tokens, result_text = engine.execute_technique("session-1", "T9002")

    assert commands_run == 1
    mock_interactor.execute_command.assert_called_once_with("whoami")

  def test_random_test_selection_runs_exactly_one_test(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9002", MIXED_PLATFORM_TECHNIQUE_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="true")

    detected, commands_run, scores, notable_tokens, result_text = engine.execute_technique("session-1", "T9002")

    assert commands_run == 1
    mock_interactor.execute_command.assert_called_once_with("whoami")

  def test_substitutes_input_argument_placeholders_in_command_and_cleanup(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9003", TECHNIQUE_WITH_ARGS_AND_CLEANUP_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="false")

    engine.execute_technique("session-1", "T9003")

    mock_interactor.execute_command.assert_called_once_with("touch /tmp/decoy.txt")

  def test_technique_without_supported_platforms_key_is_executed(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="false")

    detected, commands_run, scores, notable_tokens, result_text = engine.execute_technique("session-1", "T9004")

    assert commands_run == 1
    mock_interactor.execute_command.assert_called_once_with("pwd")

  def test_low_credibility_score_marks_honeypot_detected_and_stops_test(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="false")
    engine.analyzer.threshold = 0.5
    engine.analyzer.analyze_response.return_value = EvaluationResult("looks fake", 0.1)

    detected, commands_run, scores, notable_tokens, result_text = engine.execute_technique("session-1", "T9001")

    assert detected is True
    assert commands_run == 1
    assert scores == [0.1]

  def test_writes_one_metrics_line_per_command(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_SELECT_RANDOM_TEST="false")

    engine.execute_technique("session-42", "T9001")

    with open(metrics_file, encoding="utf-8") as f:
      lines = [json.loads(line) for line in f]

    assert len(lines) == 2
    assert all(entry["event_type"] == "command" for entry in lines)
    assert all(entry["session_id"] == "session-42" for entry in lines)
    assert {entry["command_executed"] for entry in lines} == {"whoami", "id"}


class TestRunSimulation:
  def test_aborts_if_interactor_fails_to_connect(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    mock_interactor.connect.return_value = False
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_TECHNIQUES="T9001")

    engine.run_simulation("session-1")

    mock_interactor.execute_command.assert_not_called()
    mock_interactor.disconnect.assert_not_called()

  def test_baseline_sweep_stops_pre_existing_scenery_counting_as_discovery(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_SELECT_RANDOM_TEST="false",
    )

    mock_interactor.execute_command.return_value = "redis-server.service /var/log/redis-server.log"

    baseline = engine._capture_session_baseline()
    assert "/var/log/redis-server.log" in baseline

    later = engine._extract_notable_tokens(
      "redis-server.service /var/log/redis-server.log", "systemctl status redis-server"
    )
    assert not (later - baseline), "scenery present before the attacker arrived is not a discovery"

  def test_runs_all_configured_techniques_and_disconnects(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001,T9004", LLMATTACKER_SELECT_RANDOM_TEST="false",
    )

    engine.run_simulation("session-1")

    mock_interactor.disconnect.assert_called_once()
    baseline_commands = len(engine.planner.PERIODIC_RECON_COMMANDS)
    assert mock_interactor.execute_command.call_count == baseline_commands + 3

  def test_writes_attack_simulation_summary_metrics(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_SELECT_RANDOM_TEST="false", LLMATTACKER_LEVEL="Advanced",
    )

    engine.run_simulation("session-99")

    with open(metrics_file, encoding="utf-8") as f:
      lines = [json.loads(line) for line in f]

    summary_lines = [entry for entry in lines if entry["event_type"] == "attack_simulation"]
    assert len(summary_lines) == 1
    summary = summary_lines[0]
    assert summary["session_id"] == "session-99"
    assert summary["attacker_level"] == "Advanced"
    assert summary["total_commands"] == 11
    assert summary["techniques"] == ["T9001"]
    assert summary["detected_honeypot"] is False
    assert summary["avg_credibility"] == 1.0
    assert summary["threat_actor_profile"] in THREAT_ACTOR_PROFILES

  def test_disconnects_even_if_a_technique_raises(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001",
    )
    engine.execute_technique = MagicMock(side_effect=RuntimeError("boom"))

    engine.run_simulation("session-1")

    mock_interactor.disconnect.assert_called_once()

  def test_attack_planner_reordering_is_honored(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001,T9004", LLMATTACKER_SELECT_RANDOM_TEST="false",
    )

    plan_first = json.dumps({"next_technique_id": "T9004", "reasoning": "prefer this one first"})
    plan_second = json.dumps({"next_technique_id": None, "reasoning": "done"})
    engine.planner.llm_client.chat.completions.create.side_effect = [
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_first))]),
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_second))]),
    ]

    engine.run_simulation("session-1")

    mock_interactor.execute_command.assert_any_call("pwd")
    baseline_commands = len(engine.planner.PERIODIC_RECON_COMMANDS)
    attack_calls = mock_interactor.execute_command.call_args_list[baseline_commands:]
    assert attack_calls[0].args[0] == "pwd"

  def test_bonus_technique_is_executed_when_planner_requests_it(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_BONUS_TECHNIQUES="T9004", LLMATTACKER_SELECT_RANDOM_TEST="false",
    )

    plan_use_base = json.dumps({"next_technique_id": "T9001", "reasoning": "start here"})
    plan_request_bonus = json.dumps({"next_technique_id": None, "reasoning": "very convincing, going further", "request_bonus_technique": True})
    plan_stop = json.dumps({"next_technique_id": None, "reasoning": "done now"})
    engine.planner.llm_client.chat.completions.create.side_effect = [
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_use_base))]),
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_request_bonus))]),
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_stop))]),
    ]

    engine.run_simulation("session-1")

    with open(metrics_file, encoding="utf-8") as f:
      lines = [json.loads(line) for line in f]
    summary = next(entry for entry in lines if entry["event_type"] == "attack_simulation")
    assert summary["techniques"] == ["T9001", "T9004"]
    mock_interactor.execute_command.assert_any_call("whoami")
    mock_interactor.execute_command.assert_any_call("pwd")

  def test_bonus_pool_is_not_offered_once_exhausted(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_BONUS_TECHNIQUES="T9004", LLMATTACKER_SELECT_RANDOM_TEST="false",
    )

    plan_use_base = json.dumps({"next_technique_id": "T9001", "reasoning": "start here"})
    plan_request_bonus = json.dumps({"next_technique_id": None, "reasoning": "going further", "request_bonus_technique": True})
    engine.planner.llm_client.chat.completions.create.side_effect = [
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_use_base))]),
      SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=plan_request_bonus))]),
    ]

    engine.run_simulation("session-1")

    assert engine.planner.llm_client.chat.completions.create.call_count == 2

  def test_attacker_abandons_session_after_enough_suspicious_techniques(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    write_technique(tmp_path, "T9005", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001,T9004,T9005", LLMATTACKER_SELECT_RANDOM_TEST="false",
      LLMATTACKER_PROFILE="script_kiddie",
      LLMATTACKER_LEVEL="Intermediate",
    )
    engine.execute_technique = MagicMock(return_value=(True, 2, [0.1, 0.1], set(), ""))

    engine.run_simulation("session-1")

    with open(metrics_file, encoding="utf-8") as f:
      summary = next(json.loads(line) for line in f if json.loads(line)["event_type"] == "attack_simulation")
    assert summary["abandoned_as_honeypot"] is True
    assert summary["techniques"] == ["T9001", "T9004"]

  def test_convincing_session_is_never_abandoned(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001,T9004", LLMATTACKER_SELECT_RANDOM_TEST="false",
      LLMATTACKER_PROFILE="script_kiddie",
    )
    engine.execute_technique = MagicMock(return_value=(False, 2, [1.0, 1.0], {"unique-token"}, ""))

    engine.run_simulation("session-1")

    with open(metrics_file, encoding="utf-8") as f:
      summary = next(json.loads(line) for line in f if json.loads(line)["event_type"] == "attack_simulation")
    assert summary["abandoned_as_honeypot"] is False
    assert len(summary["techniques"]) == 2

  def test_persistent_actor_tolerates_more_suspicion_than_opportunistic(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    suspicious_twice = [
      TechniqueOutcome(technique_id="T9001", commands_executed=2, honeypot_detected=True, avg_credibility=0.1),
      TechniqueOutcome(technique_id="T9004", commands_executed=1, honeypot_detected=True, avg_credibility=0.1),
    ]
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_PROFILE="nation_state_spy",
      LLMATTACKER_LEVEL="Intermediate",
    )
    assert engine._should_abandon_as_honeypot(suspicious_twice) is False

    engine_opportunistic = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_PROFILE="script_kiddie",
      LLMATTACKER_LEVEL="Intermediate",
    )
    assert engine_opportunistic._should_abandon_as_honeypot(suspicious_twice) is True

  def test_advanced_attacker_abandons_with_less_evidence_than_beginner(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    three_suspicious = [
      TechniqueOutcome(technique_id="T9001", commands_executed=2, honeypot_detected=True, avg_credibility=0.1),
      TechniqueOutcome(technique_id="T9004", commands_executed=1, honeypot_detected=True, avg_credibility=0.1),
      TechniqueOutcome(technique_id="T9005", commands_executed=1, honeypot_detected=True, avg_credibility=0.1),
    ]

    engine_beginner = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_PROFILE="corporate_spy", LLMATTACKER_LEVEL="Beginner",
    )
    engine_advanced = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_PROFILE="corporate_spy", LLMATTACKER_LEVEL="Advanced",
    )

    assert engine_beginner._should_abandon_as_honeypot(three_suspicious) is False
    assert engine_advanced._should_abandon_as_honeypot(three_suspicious) is True

  def test_attacker_abandons_a_mundane_target_even_without_suspicion(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    for i in range(4):
      write_technique(tmp_path, f"T900{i}", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9000,T9001,T9002,T9003", LLMATTACKER_SELECT_RANDOM_TEST="false",
      LLMATTACKER_PROFILE="script_kiddie",
      LLMATTACKER_LEVEL="Advanced",
    )
    engine.execute_technique = MagicMock(return_value=(False, 2, [1.0, 1.0], set(), ""))
    mock_interactor.execute_command.return_value = ""

    engine.run_simulation("session-1")

    with open(metrics_file, encoding="utf-8") as f:
      summary = next(json.loads(line) for line in f if json.loads(line)["event_type"] == "attack_simulation")
    assert summary["abandoned_as_honeypot"] is False
    assert summary["abandoned_as_uninteresting"] is True
    assert summary["techniques"] == ["T9000"]

  def test_a_single_strong_result_resets_the_boredom_streak(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_PROFILE="script_kiddie",
    )
    boring = TechniqueOutcome(technique_id="T9001", commands_executed=2, honeypot_detected=False, avg_credibility=1.0, new_notable_tokens=0)
    novel = TechniqueOutcome(
      technique_id="T9001", commands_executed=2, honeypot_detected=False,
      avg_credibility=1.0, new_notable_tokens=engine.MEANINGFUL_NOVELTY_TOKENS,
    )

    history = [boring, boring, novel]
    assert engine._should_abandon_as_uninteresting(history) is False

  def test_a_trickle_of_tokens_does_not_reset_the_boredom_streak(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_LEVEL="Advanced", LLMATTACKER_PROFILE="script_kiddie",
    )
    trickle = TechniqueOutcome(
      technique_id="T9001", commands_executed=2, honeypot_detected=False,
      avg_credibility=1.0, new_notable_tokens=engine.MEANINGFUL_NOVELTY_TOKENS - 1,
      new_artifact_classes=frozenset(),
    )

    assert engine._should_abandon_as_uninteresting([trickle] * 8) is True

  def test_boredom_check_requires_at_least_three_techniques_of_history(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_PROFILE="script_kiddie",
    )
    boring = TechniqueOutcome(technique_id="T9001", commands_executed=2, honeypot_detected=False, avg_credibility=1.0, new_notable_tokens=0)

    assert engine._should_abandon_as_uninteresting([boring, boring]) is False

  def test_intermediate_wants_volume_of_deception(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_LEVEL="Intermediate", LLMATTACKER_PROFILE="script_kiddie",
    )

    def outcome(tokens, classes):
      return TechniqueOutcome(
        technique_id="T9001", commands_executed=2, honeypot_detected=False,
        avg_credibility=1.0, new_notable_tokens=tokens,
        new_artifact_classes=frozenset(classes),
      )

    one_class = [outcome(20, {"log"}), outcome(20, {"log"})]
    many_classes = [
      outcome(10, {"log"}), outcome(10, {"process"}),
      outcome(10, {"credential"}), outcome(10, {"network"}),
      outcome(10, {"backup"}), outcome(10, {"account"}),
    ]

    dry_spell = [outcome(0, set())] * 5
    assert engine._should_abandon_as_uninteresting(one_class + dry_spell) is True
    assert engine._should_abandon_as_uninteresting(many_classes + dry_spell) is False

  def test_beginner_stays_as_long_as_any_deception_happened(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_LEVEL="Beginner", LLMATTACKER_PROFILE="script_kiddie",
    )

    def outcome(classes):
      return TechniqueOutcome(
        technique_id="T9001", commands_executed=2, honeypot_detected=False,
        avg_credibility=1.0, new_notable_tokens=6 if classes else 0,
        new_artifact_classes=frozenset(classes),
      )

    thin = [outcome({"log"}), outcome({"log"})]
    dry_spell = [outcome(set())] * 5
    assert engine._should_abandon_as_uninteresting(thin + dry_spell) is False

    assert engine._should_abandon_as_uninteresting([outcome(set())] * 5) is True

  def test_flooding_one_artifact_class_cannot_buy_unlimited_patience(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001", LLMATTACKER_LEVEL="Beginner", LLMATTACKER_PROFILE="script_kiddie",
    )
    flood = TechniqueOutcome(
      technique_id="T9001", commands_executed=2, honeypot_detected=False,
      avg_credibility=1.0, new_notable_tokens=400, new_artifact_classes=frozenset({"log"}),
    )
    boring = TechniqueOutcome(
      technique_id="T9001", commands_executed=2, honeypot_detected=False,
      avg_credibility=1.0, new_notable_tokens=0, new_artifact_classes=frozenset(),
    )

    assert engine._should_abandon_as_uninteresting([flood] + [boring] * 10) is True

  def test_corroboration_counts_one_name_carried_by_several_artifacts(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    engine = build_engine(tmp_path, mock_interactor, metrics_file, monkeypatch, LLMATTACKER_TECHNIQUES="T9001")

    coherent = {
      "/var/log/backup-runner.log", "/usr/sbin/backup-runner",
      "backup-runner.service", "/tmp/backup-runner.tmp",
    }
    unrelated = {
      "/var/log/nginx-access.log", "/usr/sbin/haproxy",
      "redis-server.service", "/tmp/session-4821.tmp",
    }

    assert engine._count_corroborated_tokens(coherent, set(), "") > 0
    assert engine._count_corroborated_tokens(unrelated, set(), "") == 0

  def test_planner_stopping_early_skips_remaining_techniques(self, tmp_path, mock_interactor, metrics_file, monkeypatch):
    write_technique(tmp_path, "T9001", LINUX_ONLY_TECHNIQUE_YAML)
    write_technique(tmp_path, "T9004", NO_SUPPORTED_PLATFORMS_KEY_YAML)
    engine = build_engine(
      tmp_path, mock_interactor, metrics_file, monkeypatch,
      LLMATTACKER_TECHNIQUES="T9001,T9004", LLMATTACKER_SELECT_RANDOM_TEST="false",
    )

    plan_stop = json.dumps({"next_technique_id": None, "reasoning": "profile is opportunistic, bailing"})
    engine.planner.llm_client.chat.completions.create.side_effect = None
    engine.planner.llm_client.chat.completions.create.return_value = SimpleNamespace(
      choices=[SimpleNamespace(message=SimpleNamespace(content=plan_stop))]
    )

    engine.run_simulation("session-1")

    executed = [call.args[0] for call in mock_interactor.execute_command.call_args_list]
    assert executed == list(engine.planner.PERIODIC_RECON_COMMANDS)
