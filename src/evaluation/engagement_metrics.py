"""Computes the engagement metrics of a session (commands, techniques, deception effort) from its recorded transcript."""

from typing import Literal

from pydantic import BaseModel, Field

from src.evaluation.models import SessionVerdict
from src.evaluation.session_evaluator import SessionEvaluator
from src.honeyengage.telemetry.models import Session


class EngagementMetrics(BaseModel):
  session_id: str = Field(..., description="The HoneyEngage session_id these metrics cover")
  attacker_tool: str = Field(..., description="Name of the tool that generated the attack traffic")

  session_duration_seconds: float | None = Field(
    None, description="Wall-clock time between session start and end, if end_time was recorded"
  )
  total_commands: int = Field(..., description="Total number of commands executed during the session")
  unique_commands: int = Field(..., description="Number of distinct command strings executed (repeats collapsed)")

  unique_attack_techniques: int = Field(
    ..., description="Number of distinct MITRE ATT&CK technique_ids HoneyEngage mapped commands to in this session"
  )
  attack_techniques: list[str] = Field(
    default_factory=list, description="The distinct technique_ids observed, in first-seen order"
  )

  unique_engage_capabilities: int = Field(
    ..., description="Number of distinct Engage deception capabilities deployed across the whole session"
  )
  total_engage_steps: int = Field(
    ..., description="Total Course-of-Action steps executed across the session (chains count every step)"
  )
  average_chain_length: float = Field(
    ..., description="Mean number of steps per Course-of-Action reaction (1.0 under single-capability mode)"
  )

  exit_reason: str | None = Field(None, description="Why the session ended, as recorded by the sensor")

  average_credibility: float | None = Field(
    None, description="Mean per-command credibility score from SessionEvaluator's judge, if computed"
  )
  detected_honeypot: bool | None = Field(
    None, description="Whether the judge's average credibility fell below its detection threshold"
  )
  commands_before_detection: int | None = Field(
    None, description="Index (1-based) of the first command whose credibility score fell below the detection "
                       "threshold; None if the honeypot was never detected in this session"
  )


def _first_index_below_threshold(verdict: SessionVerdict, threshold: float) -> int | None:
  for index, command_verdict in enumerate(verdict.command_verdicts, start=1):
    if command_verdict.credibility_score < threshold:
      return index
  return None


def compute_engagement_metrics(
  session: Session,
  attacker_tool: str = "unknown",
  evaluator: SessionEvaluator | Literal[False] | None = None,
) -> EngagementMetrics:
  interactions = session.interactions

  duration_seconds = None
  if session.session_metadata.end_time is not None:
    duration_seconds = (session.session_metadata.end_time - session.session_metadata.start_time).total_seconds()

  commands = [interaction.command for interaction in interactions]
  unique_commands = len(set(commands))

  seen_techniques: list[str] = []
  for interaction in interactions:
    if interaction.mitre_mapping and interaction.mitre_mapping.technique_id not in seen_techniques:
      seen_techniques.append(interaction.mitre_mapping.technique_id)

  capability_names: list[str] = []
  chain_lengths: list[int] = []
  for interaction in interactions:
    if interaction.engage_details is None:
      continue
    steps = interaction.engage_details.steps
    if not steps:
      continue
    chain_lengths.append(len(steps))
    capability_names.extend(step.capability_name for step in steps)

  average_chain_length = sum(chain_lengths) / len(chain_lengths) if chain_lengths else 0.0

  average_credibility = None
  detected_honeypot = None
  commands_before_detection = None

  if evaluator is not False:
    judge = evaluator or SessionEvaluator()
    verdict = judge.evaluate(session, attacker_tool=attacker_tool)
    average_credibility = verdict.average_credibility
    detected_honeypot = verdict.detected_honeypot
    commands_before_detection = _first_index_below_threshold(verdict, judge.threshold)

  return EngagementMetrics(
    session_id=session.session_id,
    attacker_tool=attacker_tool,
    session_duration_seconds=duration_seconds,
    total_commands=session.session_metadata.total_commands,
    unique_commands=unique_commands,
    unique_attack_techniques=len(seen_techniques),
    attack_techniques=seen_techniques,
    unique_engage_capabilities=len(set(capability_names)),
    total_engage_steps=len(capability_names),
    average_chain_length=round(average_chain_length, 3),
    exit_reason=session.session_metadata.exit_reason,
    average_credibility=average_credibility,
    detected_honeypot=detected_honeypot,
    commands_before_detection=commands_before_detection,
  )


def main():
  import argparse
  from pathlib import Path

  parser = argparse.ArgumentParser(
    description="Computes attacker engagement/retention metrics for a data/{session_id}.json session file."
  )
  parser.add_argument("session_file", help="Path to a data/{session_id}.json file produced by HoneyEngage.")
  parser.add_argument("--attacker-tool", default="unknown", help="Label for the tool that generated the attack.")
  parser.add_argument("--threshold", type=float, default=None, help="Credibility detection threshold override.")
  parser.add_argument("--skip-judge", action="store_true", help="Skip LLM credibility judging (structural metrics only).")
  parser.add_argument("--output", help="Optional path to write the metrics as JSON.")
  args = parser.parse_args()

  evaluator: SessionEvaluator | Literal[False] = False if args.skip_judge else SessionEvaluator(threshold=args.threshold)
  session = SessionEvaluator().load_session(args.session_file)
  metrics = compute_engagement_metrics(session, attacker_tool=args.attacker_tool, evaluator=evaluator)

  print(metrics.model_dump_json(indent=2))
  if args.output:
    Path(args.output).write_text(metrics.model_dump_json(indent=2), encoding="utf-8")


if __name__ == "__main__":
  main()
