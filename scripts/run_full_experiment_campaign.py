"""Runs the full factorial campaign defined in scripts/campaign_config.yaml (model pairs x deception condition x skill level x persona mode x repetitions) and writes one result row per session to results/campaign_results.jsonl."""
#!/usr/bin/env python3

import argparse
import csv
import itertools
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from loguru import logger

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

from orchestrator.orchestrator import run_single_session  # noqa: E402
from orchestrator.technique_pool import (  # noqa: E402
  sample_bonus_techniques_for_level,
  sample_techniques_for_level,
)
from scripts.ollama_docker_manager import (  # noqa: E402
  pull_model,
  remove_container_and_volume,
  remove_model,
  start_ollama_container,
)
from src.evaluation.engagement_metrics import compute_engagement_metrics  # noqa: E402
from src.evaluation.session_evaluator import SessionEvaluator  # noqa: E402

logger.add("logs/campaign.log", rotation="10 MB")

DEFAULT_CAMPAIGN_CONFIG = REPO_ROOT / "scripts" / "campaign_config.yaml"
RESULTS_DIR = REPO_ROOT / "results"
DATA_DIR = REPO_ROOT / "data"
LLMATTACKER_METRICS_FILE = REPO_ROOT / "attack_metrics.jsonl"


def load_campaign_config(config_path: Path) -> dict:
  with config_path.open(encoding="utf-8") as f:
    return yaml.safe_load(f)


def load_attacker_abandonment(session_id: str) -> dict:
  defaults = {
    "detected_honeypot": None,
    "abandoned_as_honeypot": None,
    "abandoned_as_uninteresting": None,
    "techniques_attempted_before_abandoning": None,
    "assigned_pool_size": None,
    "assigned_pool_exhausted": None,
    "bonus_techniques_used": None,
  }
  if not LLMATTACKER_METRICS_FILE.exists():
    return defaults

  with LLMATTACKER_METRICS_FILE.open(encoding="utf-8") as f:
    lines = f.readlines()

  for line in reversed(lines):
    line = line.strip()
    if not line:
      continue
    try:
      entry = json.loads(line)
    except json.JSONDecodeError:
      continue
    if entry.get("session_id") == session_id and entry.get("event_type") == "attack_simulation":
      return {
        "detected_honeypot": entry.get("detected_honeypot"),
        "abandoned_as_honeypot": entry.get("abandoned_as_honeypot"),
        "abandoned_as_uninteresting": entry.get("abandoned_as_uninteresting"),
        "techniques_attempted_before_abandoning": entry.get("techniques_attempted_before_abandoning"),
        "assigned_pool_size": entry.get("assigned_pool_size"),
        "assigned_pool_exhausted": entry.get("assigned_pool_exhausted"),
        "bonus_techniques_used": entry.get("bonus_techniques_used"),
      }
  return defaults


def build_session_matrix(config: dict) -> list[dict]:
  coa_modes = config.get("coa_modes", ["chain", "single"])
  persona_modes = config.get("persona_modes", ["random", "none"])
  levels = config.get("attacker_levels", ["Beginner", "Intermediate", "Advanced"])
  repetitions = config.get("repetitions", 3)

  if "model_pairs" in config:
    model_pairs = [tuple(pair) for pair in config["model_pairs"]]
  else:
    models = config["models"]
    model_pairs = list(itertools.product(models, models))

  sessions = []
  for (defender_model, attacker_model), coa_mode, persona_mode, level, iteration in itertools.product(
    model_pairs, coa_modes, persona_modes, levels, range(repetitions)
  ):
    sessions.append({
      "defender_model": defender_model,
      "attacker_model": attacker_model,
      "coa_mode": coa_mode,
      "persona_mode": persona_mode,
      "attacker_level": level,
      "iteration": iteration,
    })
  return sessions


def group_sessions_by_model_pair(sessions: list[dict]) -> list[tuple[tuple[str, str], list[dict]]]:
  order: list[tuple[str, str]] = []
  grouped: dict[tuple[str, str], list[dict]] = {}
  for session in sessions:
    key = (session["defender_model"], session["attacker_model"])
    if key not in grouped:
      grouped[key] = []
      order.append(key)
    grouped[key].append(session)
  return [(key, grouped[key]) for key in order]


def make_session_id(plan: dict) -> str:
  timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
  return (
    f"campaign-{timestamp}_DM-{plan['defender_model'].replace(':', '-').replace('/', '-')}"
    f"_AM-{plan['attacker_model'].replace(':', '-').replace('/', '-')}"
    f"_COA-{plan['coa_mode']}_PM-{plan['persona_mode']}_AL{plan['attacker_level']}_i{plan['iteration']}"
  )


def build_envs(plan: dict, session_id: str, config: dict) -> tuple[dict, dict]:
  attacker_techniques = sample_techniques_for_level(
    plan["attacker_level"], iteration=plan["iteration"], seed=plan["iteration"]
  )
  bonus_techniques = [] if plan["coa_mode"] == "static" else sample_bonus_techniques_for_level(
    plan["attacker_level"], iteration=plan["iteration"], base_techniques=attacker_techniques, seed=plan["iteration"]
  )

  honeyengage_env = os.environ.copy()
  honeyengage_env["OPENAI_BASE_URL"] = config.get("ollama_base_url", "http://localhost:11434/v1")
  honeyengage_env["OPENAI_API_KEY"] = "ollama"
  honeyengage_env["HONEYENGAGE_CORRELATION_MODEL"] = plan["defender_model"]
  honeyengage_env["HONEYENGAGE_ENGAGE_MODEL"] = plan["defender_model"]
  honeyengage_env["HONEYENGAGE_CORRELATION_ENGINE_TEMPERATURE"] = str(config.get("correlation_engine_temperature", 0.0))
  honeyengage_env["HONEYENGAGE_CORRELATION_MAX_TOKENS"] = str(config.get("correlation_max_tokens", 400))
  honeyengage_env["HONEYENGAGE_ENGAGE_ENGINE_TEMPERATURE"] = str(config.get("engage_engine_temperature", 0.5))
  honeyengage_env["HONEYENGAGE_ENGAGE_ENGINE_THRESHOLD"] = str(config.get("engage_engine_threshold", 0.6))
  honeyengage_env["HONEYENGAGE_COA_MODE"] = plan["coa_mode"]
  honeyengage_env["HONEYENGAGE_PERSONA_MODE"] = plan["persona_mode"]
  honeyengage_env["SESSION_ID"] = session_id
  honeyengage_env["ENABLE_METRICS"] = "true"
  honeyengage_env["METRICS_FILE"] = "defend_metrics.jsonl"
  honeyengage_env["HONEYENGAGE_SEED"] = str(plan["iteration"])

  llmattacker_env = os.environ.copy()
  llmattacker_env["OPENAI_BASE_URL"] = config.get("ollama_base_url", "http://localhost:11434/v1")
  llmattacker_env["OPENAI_API_KEY"] = "ollama"
  llmattacker_env["LLMATTACKER_LLM_MODEL"] = plan["attacker_model"]
  llmattacker_env["LLMATTACKER_JUDGE_MODEL"] = config.get("judge_model", "llama3.1")
  llmattacker_env["LLMATTACKER_TEMPERATURE"] = str(config.get("attacker_temperature", 0.2))
  llmattacker_env["LLMATTACKER_THRESHOLD"] = str(config.get("attacker_threshold", 0.4))
  llmattacker_env["LLMATTACKER_LEVEL"] = plan["attacker_level"]
  llmattacker_env["LLMATTACKER_TECHNIQUES"] = ",".join(attacker_techniques)
  llmattacker_env["LLMATTACKER_BONUS_TECHNIQUES"] = ",".join(bonus_techniques)
  llmattacker_env["SESSION_ID"] = session_id
  llmattacker_env["LLMATTACKER_PROFILE_SEED_KEY"] = (
    f"AM-{plan['attacker_model']}_AL{plan['attacker_level']}_PM-{plan['persona_mode']}_i{plan['iteration']}"
  )
  llmattacker_env["ENABLE_METRICS"] = "true"
  llmattacker_env["METRICS_FILE"] = "attack_metrics.jsonl"
  llmattacker_env["LLMATTACKER_SELECT_RANDOM_TEST"] = "true"
  llmattacker_env["LLMATTACKER_USER"] = config.get("attacker_user", "user")
  llmattacker_env["LLMATTACKER_PASS"] = config.get("attacker_pass", "user")
  llmattacker_env["LLMATTACKER_SEED"] = str(plan["iteration"])

  return honeyengage_env, llmattacker_env


def run_campaign(config_path: Path, skip_judge: bool, dry_run: bool, max_wait: float) -> None:
  config = load_campaign_config(config_path)
  sessions = build_session_matrix(config)
  pair_groups = group_sessions_by_model_pair(sessions)
  distinct_pairs = [pair for pair, _ in pair_groups]

  logger.info(f"Planned matrix: {len(sessions)} sessions across {len(distinct_pairs)} defender/attacker model pair(s)")

  if dry_run:
    for plan in sessions:
      print(make_session_id(plan))
    logger.info("Dry run complete; no sessions were executed.")
    return

  RESULTS_DIR.mkdir(exist_ok=True)
  DATA_DIR.mkdir(exist_ok=True)
  jsonl_path = RESULTS_DIR / "campaign_results.jsonl"
  csv_path = RESULTS_DIR / "campaign_results.csv"

  pull_timeout = config.get("pull_timeout_seconds", 1800)
  judge_model = config.get("judge_model", "llama3.1")

  start_ollama_container()
  pull_model(judge_model, timeout=pull_timeout)
  os.environ["LLMATTACKER_LLM_MODEL"] = judge_model
  evaluator: SessionEvaluator | Literal[False] = False if skip_judge else SessionEvaluator()
  loader = SessionEvaluator()
  resident_models: set[str] = set()
  try:
    for pair_index, (model_pair, pair_sessions) in enumerate(pair_groups):
      needed = set(model_pair)
      stale = resident_models - needed
      for stale_model in stale:
        remove_model(stale_model)
        resident_models.discard(stale_model)

      for model in needed - resident_models:
        pull_model(model, timeout=pull_timeout)
        resident_models.add(model)

      logger.info(
        f"=== Pair {pair_index + 1}/{len(distinct_pairs)}: defender='{model_pair[0]}' "
        f"attacker='{model_pair[1]}' ({len(pair_sessions)} session(s)) ==="
      )

      for plan in pair_sessions:
        session_id = make_session_id(plan)
        logger.info(f"--- Running session {session_id} ---")

        honeyengage_env, llmattacker_env = build_envs(plan, session_id, config)
        succeeded = run_single_session(session_id, honeyengage_env, llmattacker_env, data_dir=str(DATA_DIR), max_wait=max_wait)

        record = dict(plan)
        record["session_id"] = session_id
        record["session_completed"] = succeeded
        record["timestamp"] = datetime.now(UTC).isoformat()

        if succeeded:
          try:
            session = loader.load_session(DATA_DIR / f"{session_id}.json")
            metrics = compute_engagement_metrics(session, attacker_tool=plan["attacker_model"], evaluator=evaluator)
            record.update(metrics.model_dump())
            record.update(load_attacker_abandonment(session_id))
          except Exception as exc:
            logger.error(f"Failed to compute metrics for {session_id}: {exc}")
            record["metrics_error"] = str(exc)

        with jsonl_path.open("a", encoding="utf-8") as f:
          f.write(json.dumps(record, default=str) + "\n")

  finally:
    remove_container_and_volume()

  _write_csv_from_jsonl(jsonl_path, csv_path)
  logger.success(f"Campaign complete. Results: {jsonl_path} and {csv_path}")


def _write_csv_from_jsonl(jsonl_path: Path, csv_path: Path) -> None:
  if not jsonl_path.exists():
    return

  records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
  if not records:
    return

  fieldnames: list[str] = []
  for record in records:
    for key in record:
      if key not in fieldnames:
        fieldnames.append(key)

  with csv_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for record in records:
      writer.writerow({k: record.get(k, "") for k in fieldnames})


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("--config", type=Path, default=DEFAULT_CAMPAIGN_CONFIG, help="Path to the campaign YAML config.")
  parser.add_argument("--skip-judge", action="store_true", help="Skip LLM credibility judging (faster, structural metrics only).")
  parser.add_argument("--dry-run", action="store_true", help="Print the planned session matrix and exit without running anything.")
  parser.add_argument("--max-wait", type=float, default=300.0, help="Max seconds to wait for a session's data file before giving up.")
  args = parser.parse_args()

  run_campaign(args.config, skip_judge=args.skip_judge, dry_run=args.dry_run, max_wait=args.max_wait)


if __name__ == "__main__":
  main()
