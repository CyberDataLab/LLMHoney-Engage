"""Post-hoc credibility evaluation of a recorded session transcript."""

import json
from pathlib import Path

from loguru import logger

from src.evaluation.models import CommandVerdict, SessionVerdict
from src.honeyengage.telemetry.models import Session
from src.llmattacker.deception_engine.credibility_analyzer import CredibilityAnalyzer

logger.add("logs/session_evaluator.log", rotation="1 MB")

DEFAULT_DETECTION_THRESHOLD = 0.5


class SessionEvaluator:

  def __init__(self, threshold: float | None = None):
    self.analyzer = CredibilityAnalyzer()
    self.threshold = threshold if threshold is not None else DEFAULT_DETECTION_THRESHOLD

  def load_session(self, session_path: str | Path) -> Session:
    path = Path(session_path)
    with path.open("r", encoding="utf-8") as f:
      return Session.model_validate(json.load(f))

  def evaluate_session(self, session_path: str | Path, attacker_tool: str = "unknown") -> SessionVerdict:
    session = self.load_session(session_path)
    return self.evaluate(session, attacker_tool)

  def evaluate(self, session: Session, attacker_tool: str = "unknown") -> SessionVerdict:
    command_verdicts: list[CommandVerdict] = []

    for interaction in session.interactions:
      if interaction.response is None:
        logger.warning(f"No captured response for command '{interaction.command}' in session {session.session_id}; skipping.")
        continue

      evaluation = self.analyzer.analyze_response(interaction.command, interaction.response, oracle_output="")

      command_verdicts.append(CommandVerdict(
        command=interaction.command,
        response=interaction.response,
        predicted_technique=interaction.mitre_mapping.technique_id if interaction.mitre_mapping else None,
        engage_capabilities_used=[step.capability_name for step in interaction.engage_details.steps] if interaction.engage_details else [],
        credibility_score=evaluation.score,
        reasoning=evaluation.reasoning,
        judge_error=evaluation.error,
      ))

    if command_verdicts:
      average_credibility = sum(v.credibility_score for v in command_verdicts) / len(command_verdicts)
      lowest_scoring_command = min(command_verdicts, key=lambda v: v.credibility_score)
    else:
      average_credibility = 1.0
      lowest_scoring_command = None

    return SessionVerdict(
      session_id=session.session_id,
      attacker_tool=attacker_tool,
      total_commands_judged=len(command_verdicts),
      average_credibility=round(average_credibility, 3),
      detected_honeypot=average_credibility < self.threshold,
      lowest_scoring_command=lowest_scoring_command,
      command_verdicts=command_verdicts,
    )


def main():
  import argparse

  parser = argparse.ArgumentParser(
    description="Judges, after the fact, whether an attacker session against HoneyEngage saw through the deception."
  )
  parser.add_argument("session_file", help="Path to a data/{session_id}.json file produced by HoneyEngage.")
  parser.add_argument("--attacker-tool", default="unknown", help="Label for the tool that generated the attack (e.g. llmattacker, hackingbuddygpt).")
  parser.add_argument("--threshold", type=float, default=DEFAULT_DETECTION_THRESHOLD, help="Average credibility below which the session is marked as having detected the honeypot.")
  parser.add_argument("--output", help="Optional path to write the full verdict as JSON. Prints a summary to stdout regardless.")
  args = parser.parse_args()

  evaluator = SessionEvaluator(threshold=args.threshold)
  verdict = evaluator.evaluate_session(args.session_file, attacker_tool=args.attacker_tool)

  print(f"Session:              {verdict.session_id}")
  print(f"Attacker tool:        {verdict.attacker_tool}")
  print(f"Commands judged:      {verdict.total_commands_judged}")
  print(f"Average credibility:  {verdict.average_credibility}")
  print(f"Detected honeypot:    {verdict.detected_honeypot}")
  if verdict.lowest_scoring_command:
    print(f"Weakest moment:       '{verdict.lowest_scoring_command.command}' (score {verdict.lowest_scoring_command.credibility_score})")
    print(f"  Reasoning:          {verdict.lowest_scoring_command.reasoning}")

  if args.output:
    Path(args.output).write_text(verdict.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nFull verdict written to {args.output}")


if __name__ == "__main__":
  main()
