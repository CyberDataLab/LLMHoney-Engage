"""Checks that the pinned MITRE ATT&CK and Engage datasets match the hashes recorded in DATASETS.md."""
#!/usr/bin/env python3

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PINNED_DATASETS = {
  "enterprise-attack.json": "fc783039f17fba646f79448f1322996457c658a9474f6d14c3bc924a2cf1c97d",
  "src/honeyengage/engage_engine/Engage-Data-V1.0.xlsx": "c4449827086ebee0b1f3852cb21bbbf76be73640acd04b782a002191c4b01700",
}


def sha256_of(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def main() -> int:
  ok = True
  for relative_path, expected_hash in PINNED_DATASETS.items():
    path = REPO_ROOT / relative_path
    if not path.exists():
      print(f"[MISSING] {relative_path}")
      ok = False
      continue

    actual_hash = sha256_of(path)
    if actual_hash == expected_hash:
      print(f"[OK] {relative_path}")
    else:
      print(f"[MISMATCH] {relative_path}\n  expected: {expected_hash}\n  actual:   {actual_hash}")
      ok = False

  if not ok:
    print("\nDataset verification failed. See DATASETS.md for how to update the pinned hashes.")
    return 1

  print("\nAll pinned datasets match DATASETS.md.")
  return 0


if __name__ == "__main__":
  sys.exit(main())
