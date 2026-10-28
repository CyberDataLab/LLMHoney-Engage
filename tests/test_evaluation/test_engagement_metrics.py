import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.evaluation.engagement_metrics import compute_engagement_metrics
from src.evaluation.session_evaluator import SessionEvaluator
from src.honeyengage.telemetry.models import Session
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


def session_dict(interactions: list[dict], session_id: str = "test-session", duration_seconds: float = 120.0, exit_reason: str = "User requested logout") -> dict:
  start = datetime.now(UTC)
  end = start + timedelta(seconds=duration_seconds)
  return {
    "session_id": session_id,
    "network": {"source_ip": "10.0.0.5", "source_port": 55123, "ssh_client": "SSH-2.0-libssh"},
    "environment": {"terminal_type": "xterm", "shell_width": 80, "shell_height": 24},
    "authentication": {"username": "admin", "password": "admin", "timestamp": start.isoformat()},
    "interactions": interactions,
    "session_metadata": {
      "start_time": start.isoformat(), "end_time": end.isoformat(),
      "total_commands": len(interactions), "exit_reason": exit_reason,
    },
  }


def interaction(command: str, response: str | None, technique: str | None = None, capabilities: list[str] | None = None) -> dict:
  engage_details = None
  if capabilities:
    steps = [
      {"result_status": "success", "capability_name": name, "eac_id": "EAC0005", "error_message": ""}
      for name in capabilities
    ]
    engage_details = {
      "result_status": "success", "capability_name": capabilities[-1], "eac_id": "EAC0005", "error_message": "",
      "steps": steps, "plan_reasoning": "",
    }
  mitre_mapping = {"technique_id": technique, "confidence": 0.9, "cti_sentence": "test"} if technique else None
  return {
    "command": command, "timestamp": datetime.now(UTC).isoformat(), "backspaces": 0,
    "response": response, "mitre_mapping": mitre_mapping, "engage_details": engage_details,
  }


class TestStructuralMetricsWithoutJudge:
  def test_counts_total_and_unique_commands(self):
    session = Session.model_validate(session_dict([
      interaction("whoami", "root"),
      interaction("whoami", "root"),
      interaction("ls -la", "file1 file2"),
    ]))

    metrics = compute_engagement_metrics(session, attacker_tool="synthetic-test", evaluator=False)

    assert metrics.total_commands == 3
    assert metrics.unique_commands == 2

  def test_session_duration_is_computed_from_start_and_end_time(self):
    session = Session.model_validate(session_dict([interaction("whoami", "root")], duration_seconds=42.0))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.session_duration_seconds == pytest.approx(42.0, abs=0.5)

  def test_missing_end_time_yields_none_duration(self):
    raw = session_dict([interaction("whoami", "root")])
    raw["session_metadata"]["end_time"] = None
    session = Session.model_validate(raw)

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.session_duration_seconds is None

  def test_counts_distinct_attack_techniques_in_first_seen_order(self):
    session = Session.model_validate(session_dict([
      interaction("cat /etc/passwd", "root:x:0:0", technique="T1003.008"),
      interaction("whoami", "root", technique="T1033"),
      interaction("cat /etc/shadow", "root:$6$", technique="T1003.008"),
    ]))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.unique_attack_techniques == 2
    assert metrics.attack_techniques == ["T1003.008", "T1033"]

  def test_no_mitre_mapping_is_not_counted(self):
    session = Session.model_validate(session_dict([interaction("ls", "file1")]))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.unique_attack_techniques == 0
    assert metrics.attack_techniques == []

  def test_counts_distinct_and_total_engage_capabilities(self):
    session = Session.model_validate(session_dict([
      interaction("cat /etc/passwd", "root:x:0:0", capabilities=["CreateFakeUserAccountCapability", "ModifyBashHistoryCapability"]),
      interaction("ps aux", "fake list", capabilities=["ModifyBashHistoryCapability"]),
    ]))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.unique_engage_capabilities == 2
    assert metrics.total_engage_steps == 3

  def test_average_chain_length_reflects_course_of_action_steps(self):
    session = Session.model_validate(session_dict([
      interaction("cat /etc/passwd", "x", capabilities=["A", "B", "C"]),
      interaction("ps aux", "y", capabilities=["A"]),
    ]))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.average_chain_length == pytest.approx(2.0)

  def test_no_engage_reactions_yields_zero_chain_length(self):
    session = Session.model_validate(session_dict([interaction("ls", "file1")]))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.average_chain_length == 0.0
    assert metrics.total_engage_steps == 0
    assert metrics.unique_engage_capabilities == 0

  def test_exit_reason_is_carried_through(self):
    session = Session.model_validate(session_dict([interaction("exit", "")], exit_reason="Client disconnected"))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.exit_reason == "Client disconnected"

  def test_skip_judge_leaves_credibility_fields_none(self):
    session = Session.model_validate(session_dict([interaction("whoami", "root")]))

    metrics = compute_engagement_metrics(session, evaluator=False)

    assert metrics.average_credibility is None
    assert metrics.detected_honeypot is None
    assert metrics.commands_before_detection is None

  def test_attacker_tool_label_is_carried_through(self):
    session = Session.model_validate(session_dict([interaction("whoami", "root")]))

    metrics = compute_engagement_metrics(session, attacker_tool="hackingbuddygpt", evaluator=False)

    assert metrics.attacker_tool == "hackingbuddygpt"


class TestMetricsWithJudge:
  def test_commands_before_detection_marks_first_low_scoring_command(self, real_credibility_analyzer):
    def fake_create(**kwargs):
      user_content = kwargs["messages"][1]["content"]
      score = 0.1 if "ps aux" in user_content else 0.9
      return make_llm_response(json.dumps({"reasoning": "r", "verdict": "v", "score": score}))

    real_credibility_analyzer.client.chat.completions.create.side_effect = fake_create
    session = Session.model_validate(session_dict([
      interaction("whoami", "root"),
      interaction("ps aux", "fake process list"),
      interaction("id", "uid=0(root)"),
    ]))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator(threshold=0.5)
      metrics = compute_engagement_metrics(session, evaluator=evaluator)

    assert metrics.commands_before_detection == 2
    assert metrics.detected_honeypot is False
    assert metrics.average_credibility == pytest.approx(0.633, abs=0.001)

  def test_never_detected_yields_none_commands_before_detection(self, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "r", "verdict": "v", "score": 0.95})
    )
    session = Session.model_validate(session_dict([interaction("whoami", "root"), interaction("id", "uid=0")]))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      evaluator = SessionEvaluator(threshold=0.5)
      metrics = compute_engagement_metrics(session, evaluator=evaluator)

    assert metrics.commands_before_detection is None
    assert metrics.detected_honeypot is False

  def test_default_evaluator_is_constructed_when_none_passed(self, real_credibility_analyzer):
    real_credibility_analyzer.client.chat.completions.create.return_value = make_llm_response(
      json.dumps({"reasoning": "r", "verdict": "v", "score": 0.8})
    )
    session = Session.model_validate(session_dict([interaction("whoami", "root")]))

    with patch("src.evaluation.session_evaluator.CredibilityAnalyzer", return_value=real_credibility_analyzer):
      metrics = compute_engagement_metrics(session)

    assert metrics.average_credibility == 0.8


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
