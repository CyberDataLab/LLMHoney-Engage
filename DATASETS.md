# Pinned reference datasets

HoneyEngage depends on two external MITRE datasets checked into this repository.
Both are frozen snapshots: MITRE updates ATT&CK and Engage independently of
this project's release cycle, so the exact snapshot used must be recorded to
let anyone reproduce a reported result.

Run `python scripts/verify_datasets.py` to confirm the files in the working
tree still match the hashes below. If it fails, either the datasets were
refreshed intentionally (update this table) or they were modified/corrupted
unintentionally (restore from git).

| File | Source | Version / snapshot date | SHA-256 | Size |
|---|---|---|---|---|
| `enterprise-attack.json` | [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data), Enterprise domain | Enterprise ATT&CK 2.0, matrix last modified 2026-04-14T22:56:22.555Z | `fc783039f17fba646f79448f1322996457c658a9474f6d14c3bc924a2cf1c97d` | 47,450,483 bytes |
| `src/honeyengage/engage_engine/Engage-Data-V1.0.xlsx` | [MITRE Engage](https://engage.mitre.org/) | Engage Data V1.0 | `c4449827086ebee0b1f3852cb21bbbf76be73640acd04b782a002191c4b01700` | 164,510 bytes |

## Why this matters

- `src/honeyengage/telemetry/tracker.py::_load_attack_data` parses
  `enterprise-attack.json` to build the list of valid ATT&CK technique IDs and
  their descriptions; a newer/older ATT&CK release can add, remove, or reword
  techniques, changing what the correlation LLM is allowed to predict.
- `src/honeyengage/engage_engine/engage_parser.py::EngageParser` parses the Engage
  workbook (via `engage_mapping_cache.json`, its cached derivation) to map a
  detected technique to MITRE Engage goals/approaches/activities/vulnerabilities.
- Any published result (accuracy, deception success rate, etc.) implicitly
  depends on which snapshot of these two datasets was in place. Report the
  hashes above (or updated ones, if you refresh the datasets) alongside your
  results.

## Updating the datasets

1. Download the new `enterprise-attack.json` from the ATT&CK STIX data repo
   (Enterprise domain) or export a new `Engage-Data-V1.0.xlsx` from MITRE Engage.
2. Replace the file in the repo.
3. Delete `src/honeyengage/engage_engine/engage_mapping_cache.json` if the Engage
   workbook changed — it is a cache derived from the workbook and is rebuilt
   automatically on the next `EngageParser()` construction.
4. Recompute the hash (`sha256sum <file>`) and update the table above.
