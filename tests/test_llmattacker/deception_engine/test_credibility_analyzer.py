from types import SimpleNamespace
from unittest.mock import patch

from src.llmattacker.deception_engine.credibility_analyzer import CredibilityAnalyzer


def make_llm_response(content):
  return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


class TestCredibilityAnalyzer:
  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_init_reads_config_from_env(self, mock_openai, monkeypatch):
    monkeypatch.setenv("LLMATTACKER_THRESHOLD", "0.7")
    monkeypatch.setenv("LLMATTACKER_TEMPERATURE", "0.3")
    monkeypatch.setenv("LLMATTACKER_LLM_MODEL", "phi3")

    analyzer = CredibilityAnalyzer()

    assert analyzer.threshold == 0.7
    assert analyzer.temperature == 0.3
    assert analyzer.model == "phi3"

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_setters_override_config(self, mock_openai):
    analyzer = CredibilityAnalyzer()

    analyzer.set_threshold(0.9)
    analyzer.set_temperature(0.5)
    analyzer.set_llm_model("qwen2:7b")

    assert analyzer.threshold == 0.9
    assert analyzer.temperature == 0.5
    assert analyzer.model == "qwen2:7b"

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_identical_output_short_circuits_to_full_credibility(self, mock_openai):
    analyzer = CredibilityAnalyzer()

    result = analyzer.analyze_response("uptime", "up 2 days", "up 2 days")

    assert result.score == 1.0
    assert result.error is False
    analyzer.client.chat.completions.create.assert_not_called()

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_silent_redirection_short_circuits_to_full_credibility(self, mock_openai):
    analyzer = CredibilityAnalyzer()

    result = analyzer.analyze_response("echo hi > /tmp/f.txt", "", "")

    assert result.score == 1.0
    analyzer.client.chat.completions.create.assert_not_called()

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_vbox_artifacts_are_sanitized_before_comparison(self, mock_openai):
    analyzer = CredibilityAnalyzer()

    oracle_output = "System vendor: innotek GmbH"
    honeypot_output = "System vendor:"

    result = analyzer.analyze_response("dmidecode -s system-manufacturer", honeypot_output, oracle_output)

    assert result.score == 1.0
    analyzer.client.chat.completions.create.assert_not_called()

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_calls_llm_with_oracle_differential_prompt_when_oracle_available(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(
      '{"reasoning": "Matches structurally", "verdict": "Credible", "score": 0.9}'
    )

    result = analyzer.analyze_response("ps -aux", "USER PID %CPU ...", "USER PID %CPU ... (real)")

    assert result.score == 0.9
    assert result.reasoning == "Matches structurally"
    assert result.error is False

    call_kwargs = analyzer.client.chat.completions.create.call_args.kwargs
    system_prompt = call_kwargs["messages"][0]["content"]
    assert "Differential Testing" in system_prompt
    assert "Oracle" in call_kwargs["messages"][1]["content"]

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_calls_llm_with_generic_prompt_when_oracle_unavailable(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(
      '{"reasoning": "Looks plausible", "verdict": "Credible", "score": 0.8}'
    )

    result = analyzer.analyze_response("uname -a", "Linux ubuntu 5.15.0", "ORACLE_UNAVAILABLE")

    assert result.score == 0.8
    call_kwargs = analyzer.client.chat.completions.create.call_args.kwargs
    system_prompt = call_kwargs["messages"][0]["content"]
    assert "Differential Testing" not in system_prompt

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_oracle_not_connected_sentinel_uses_generic_prompt(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(
      '{"reasoning": "Sterile output", "verdict": "Suspicious", "score": 0.3}'
    )

    result = analyzer.analyze_response("ls -la /home", "total 0", "ORACLE_NOT_CONNECTED")

    assert result.score == 0.3
    system_prompt = analyzer.client.chat.completions.create.call_args.kwargs["messages"][0]["content"]
    assert "Differential Testing" not in system_prompt
    assert "ORACLE_NOT_CONNECTED" not in analyzer.client.chat.completions.create.call_args.kwargs["messages"][1]["content"]

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_parses_json_wrapped_in_markdown_fence(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(
      '```json\n{"reasoning": "fenced", "verdict": "Fake", "score": 0.1}\n```'
    )

    result = analyzer.analyze_response("whoami", "definitely-not-root-format", "root")

    assert result.score == 0.1
    assert result.reasoning == "fenced"

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_falls_back_to_regex_when_llm_returns_invalid_json(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(
      'reasoning: "looks broken", score: 0.25'
    )

    result = analyzer.analyze_response("ps -aux", "garbage output", "real output")

    assert result.score == 0.25
    assert result.reasoning == "looks broken"

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_score_is_clamped_to_valid_range(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(
      '{"reasoning": "over the top", "verdict": "Credible", "score": 5.0}'
    )

    result = analyzer.analyze_response("ps -aux", "some output", "real output")

    assert result.score == 1.0

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_empty_llm_response_defaults_to_full_credibility_with_error_flag(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.return_value = make_llm_response(None)

    result = analyzer.analyze_response("ps -aux", "some output", "real output")

    assert result.score == 1.0
    assert result.error is True

  @patch("src.llmattacker.deception_engine.credibility_analyzer.OpenAI")
  def test_llm_exception_defaults_to_full_credibility_with_error_flag(self, mock_openai):
    analyzer = CredibilityAnalyzer()
    analyzer.client.chat.completions.create.side_effect = RuntimeError("connection refused")

    result = analyzer.analyze_response("ps -aux", "some output", "real output")

    assert result.score == 1.0
    assert result.error is True
