import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.evaluation.session_evaluator import SessionEvaluator
from src.llmattacker.deception_engine.credibility_analyzer import CredibilityAnalyzer


def make_llm_response(content):
  return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


@pytest.fixture
def real_credibility_analyzer():
  analyzer = CredibilityAnalyzer.__new__(CredibilityAnalyzer)
  analyzer.threshold = 0.5
  analyzer.temperature = 0.0
  analyzer.model = "test-model"
  analyzer.max_tokens = 50
  analyzer.client = MagicMock()
  return analyzer


def session_dict(interactions: list[dict], session_id: str = "test-session") -> dict:
  now = datetime.now(UTC).isoformat()
  return {
    "session_id": session_id,
    "network": {"source_ip": "10.0.0.5", "source_port": 55123, "ssh_client": "SSH-2.0-libssh"},
    "environment": {"terminal_type": "xterm", "shell_width": 80, "shell_height": 24},
    "authentication": {"username": "admin", "password": "admin", "timestamp": now},
    "interactions": interactions,
    "session_metadata": {"start_time": now, "end_time": now, "total_commands": len(interactions), "exit_reason": "User requested logout"},
  }


def interaction(command: str, response: str | None, technique: str | None = None, capability: str | None = None) -> dict:
  engage_details = None
  if capability:
    engage_details = {
      "result_status": "success", "capability_name": capability, "eac_id": "EAC0005", "error_message": "",
      "steps": [{"result_status": "success", "capability_name": capability, "eac_id": "EAC0005", "error_message": ""}],
      "plan_reasoning": "",
    }
  mitre_mapping = {"technique_id": technique, "confidence": 0.9, "cti_sentence": "test"} if technique else None
  return {
    "command": command, "timestamp": datetime.now(UTC).isoformat(), "backspaces": 0,
    "response": response, "mitre_mapping": mitre_mapping, "engage_details": engage_details,
  }


class TestSessionEvaluator:
  def test_credible_session_is_not_flagged_as_detected(self, tmp_path, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "Plausible output.", "verdict": "Credible", "score": 0.95})
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([interaction("whoami", "root\r\n")])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator(threshold=0.5)
      verdict = evaluator.evaluate_session(session_path, attacker_tool="synthetic-test")

    assert verdict.detected_honeypot is False
    assert verdict.average_credibility == 0.95
    assert verdict.total_commands_judged == 1

  def test_fake_looking_session_is_flagged_as_detected(self, tmp_path, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "Structurally broken output.", "verdict": "Fake", "score": 0.05})
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([interaction("ps aux", "definitely not a real process list")])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator(threshold=0.5)
      verdict = evaluator.evaluate_session(session_path, attacker_tool="synthetic-test")

    assert verdict.detected_honeypot is True
    assert verdict.average_credibility == 0.05

  def test_identifies_the_lowest_scoring_command(self, tmp_path, real_credibility_analyzer):
    def fake_create(**kwargs):
      user_content = kwargs["messages"][1]["content"]
      score = 0.1 if "ps aux" in user_content else 0.9
      return make_llm_response(json.dumps({"reasoning": "r", "verdict": "v", "score": score}))

    real_credibility_analyzer.client.chat.completions.create.side_effect = fake_create
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([
      interaction("whoami", "root\r\n"),
      interaction("ps aux", "fake process list"),
    ])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator()
      verdict = evaluator.evaluate_session(session_path)

    assert verdict.lowest_scoring_command is not None
    assert verdict.lowest_scoring_command.command == "ps aux"

  def test_skips_interactions_without_a_captured_response(self, tmp_path, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "r", "verdict": "v", "score": 1.0})
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([
      interaction("whoami", "root\r\n"),
      interaction("uncaptured_command", None),
    ])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator()
      verdict = evaluator.evaluate_session(session_path)

    assert verdict.total_commands_judged == 1

  def test_session_with_no_judgeable_commands_defaults_to_not_detected(self, tmp_path, real_credibility_analyzer):
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([interaction("uncaptured", None)])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator()
      verdict = evaluator.evaluate_session(session_path)

    assert verdict.total_commands_judged == 0
    assert verdict.detected_honeypot is False
    assert verdict.lowest_scoring_command is None

  def test_carries_through_mitre_mapping_and_engage_capabilities(self, tmp_path, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "r", "verdict": "v", "score": 0.8})
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([
      interaction("ps aux", "fake list", technique="T1057", capability="InjectFakeProcessCapability"),
    ])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator()
      verdict = evaluator.evaluate_session(session_path)

    verdict_entry = verdict.command_verdicts[0]
    assert verdict_entry.predicted_technique == "T1057"
    assert verdict_entry.engage_capabilities_used == ["InjectFakeProcessCapability"]

  def test_attacker_tool_label_is_recorded_verbatim(self, tmp_path, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "r", "verdict": "v", "score": 1.0})
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([interaction("whoami", "root\r\n")])))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator()
      verdict = evaluator.evaluate_session(session_path, attacker_tool="hackingbuddygpt")

    assert verdict.attacker_tool == "hackingbuddygpt"

  def test_works_regardless_of_which_tool_produced_the_session(self, tmp_path, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "r", "verdict": "v", "score": 0.7})
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session_dict([interaction("id", "uid=0(root) gid=0(root)")], session_id="from-any-tool")))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator()
      verdict_a = evaluator.evaluate_session(session_path, attacker_tool="llmattacker")
      verdict_b = evaluator.evaluate_session(session_path, attacker_tool="hackingbuddygpt")

    assert verdict_a.average_credibility == verdict_b.average_credibility
    assert verdict_a.command_verdicts[0].command == verdict_b.command_verdicts[0].command
