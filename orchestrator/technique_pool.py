"""Builds the ATT&CK technique pool of each attacker skill level from the Linux Atomic Red Team tests and samples a reproducible subset per session."""

import hashlib
import json
import random
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_ATTACK_PATH = REPO_ROOT / "enterprise-attack.json"
ATOMICS_DIR = REPO_ROOT / "src" / "llmattacker" / "atomics"

LEVEL_TACTICS: dict[str, list[str]] = {
  "Beginner": ["reconnaissance", "discovery"],
  "Intermediate": ["credential-access", "collection", "execution", "lateral-movement"],
  "Advanced": ["privilege-escalation", "defense-impairment", "persistence", "command-and-control", "exfiltration", "impact"],
}

DEFAULT_SAMPLE_SIZE: dict[str, int] = {
  "Beginner": 6,
  "Intermediate": 12,
  "Advanced": 20,
}

DEFAULT_BONUS_SAMPLE_SIZE: dict[str, int] = {
  "Beginner": 2,
  "Intermediate": 4,
  "Advanced": 6,
}


def _technique_external_id(technique_obj: dict) -> str | None:
  for ref in technique_obj.get("external_references", []):
    if ref.get("source_name") == "mitre-attack":
      return ref.get("external_id")
  return None


def _load_technique_tactics() -> dict[str, list[str]]:
  with ENTERPRISE_ATTACK_PATH.open(encoding="utf-8") as f:
    bundle = json.load(f)

  mapping: dict[str, list[str]] = {}
  for obj in bundle["objects"]:
    if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
      continue
    technique_id = _technique_external_id(obj)
    if not technique_id:
      continue
    tactics = sorted({
      phase["phase_name"] for phase in obj.get("kill_chain_phases", [])
      if phase.get("kill_chain_name") == "mitre-attack"
    })
    mapping[technique_id] = tactics
  return mapping


def _is_linux_supported(test: dict) -> bool:
  supported_platforms = [platform.lower() for platform in test.get("supported_platforms", [])]
  return not supported_platforms or "linux" in supported_platforms


def _has_linux_atomic_test(yaml_path: Path) -> bool:
  try:
    with yaml_path.open(encoding="utf-8") as f:
      data = yaml.safe_load(f)
  except Exception:
    return False
  atomic_tests = data.get("atomic_tests", []) if isinstance(data, dict) else []
  return any(_is_linux_supported(test) for test in atomic_tests)


def _available_atomic_technique_ids() -> set[str]:
  if not ATOMICS_DIR.exists():
    return set()
  return {
    entry.name for entry in ATOMICS_DIR.iterdir()
    if entry.is_dir() and entry.name.startswith("T")
    and _has_linux_atomic_test(entry / f"{entry.name}.yaml")
  }


def build_technique_pools() -> dict[str, list[str]]:
  technique_tactics = _load_technique_tactics()
  available = _available_atomic_technique_ids()

  pools: dict[str, list[str]] = {}
  for level, tactics in LEVEL_TACTICS.items():
    tactic_set = set(tactics)
    pool = sorted(
      tid for tid in available
      if tactic_set.intersection(technique_tactics.get(tid, []))
    )
    pools[level] = pool
  return pools


def _repetition_rng(seed: str | int, level: str, iteration: int) -> random.Random:
  digest = hashlib.sha256(f"{seed}:techniques:{level}:{iteration}".encode()).hexdigest()
  return random.Random(int(digest, 16))


def sample_techniques_for_level(
  level: str,
  iteration: int,
  seed: str | int = 0,
  sample_size: int | None = None,
  pools: dict[str, list[str]] | None = None,
) -> list[str]:
  pools = pools if pools is not None else build_technique_pools()
  pool = pools.get(level, [])
  if not pool:
    return []

  n = sample_size if sample_size is not None else DEFAULT_SAMPLE_SIZE.get(level, 3)
  n = min(n, len(pool))

  rng = _repetition_rng(seed, level, iteration)
  return sorted(rng.sample(pool, n))


def sample_bonus_techniques_for_level(
  level: str,
  iteration: int,
  base_techniques: list[str],
  seed: str | int = 0,
  sample_size: int | None = None,
  pools: dict[str, list[str]] | None = None,
) -> list[str]:
  pools = pools if pools is not None else build_technique_pools()
  pool = [tid for tid in pools.get(level, []) if tid not in set(base_techniques)]
  if not pool:
    return []

  n = sample_size if sample_size is not None else DEFAULT_BONUS_SAMPLE_SIZE.get(level, 2)
  n = min(n, len(pool))

  digest = hashlib.sha256(f"{seed}:bonus_techniques:{level}:{iteration}".encode()).hexdigest()
  rng = random.Random(int(digest, 16))
  return sorted(rng.sample(pool, n))
