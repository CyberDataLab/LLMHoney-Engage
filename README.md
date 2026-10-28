# LLMHoney-Engage

**LLMHoney-Engage** is an SSH honeypot that practises *narrative deception*, together with an autonomous LLM attacker built to evaluate it.

When the attacker runs a command, the honeypot works out which MITRE ATT&CK technique it belongs to. It then answers with a *scenario* chosen through MITRE Engage. A scenario is a short, plausible event, such as a backup job that failed and left a log, a temporary file, and a running process behind. Its artifacts share one name and back each other up, instead of being isolated decoys.

The repository contains two systems that talk to each other only through a real SSH session:

| System | Role | Package |
|---|---|---|
| **HoneyEngage** | Defender: an emulated Ubuntu 22.04 host that reacts to the attacker with Engage-driven scenarios | `src/honeyengage` |
| **LLMAttacker** | Attacker: an autonomous agent that runs ATT&CK techniques and decides by explicit rules when to leave | `src/llmattacker` |

---

## How it works

```
             LLMAttacker                                   HoneyEngage
 ┌──────────────────────────────┐                ┌────────────────────────────────┐
 │ Threat Actor Profile         │                │ Machine Persona (server role)  │
 │ Attack Planner (LLM)         │   SSH :2222    │ Technique Correlator (LLM)     │
 │ Actions on the Victim Machine│ ─────────────▶ │ MITRE Engage Planner (LLM)     │
 │ Credibility Judge (LLM)      │ ◀───────────── │ Artifact Factory (LLM)         │
 │ Detection / loss-of-interest │   outputs      │ Emulated Ubuntu host (no LLM)  │
 └──────────────────────────────┘                └────────────────────────────────┘
                    └──────────── shared Ollama server (stateless calls) ─────────┘
```

### HoneyEngage (defender)

1. **Emulated host.** The host has a virtual file system, a process table, network state, systemd units, and a package database. It answers every command without a language model.
2. **Machine Persona.** Each session draws one of six server roles: web server, database server, CI/CD runner, file and backup server, mail relay, or developer workstation. The role sets the packages and services the host shows, and filters out scenarios that would not fit it.
3. **Technique Correlator.** A language model maps each command, together with the five commands before it, to an ATT&CK technique and a confidence. The defender reacts only when the confidence is at least 0.6.
4. **MITRE Engage Planner.** It maps the technique to Engage activities, keeps the scenario templates that fit the persona and have not been used yet, and asks a language model to choose one. There are 57 templates, defined in `engage_engine/scenario_catalog.py`.
5. **Artifact Factory.** It writes all the artifacts of the scenario in a single model call, around one shared *subject*, and plants them on the host. The artifacts can be files, logs, processes, accounts, keys, network interfaces, or services, and they appear as soon as they are ready.

The defender can run in four deception conditions, set with `HONEYENGAGE_COA_MODE`:

| Condition | What the defender plants after each identified technique |
|---|---|
| `static` | Nothing (a conventional honeypot) |
| `same_ttp` | Up to four capabilities, always from the same Engage activity |
| `multi_ttp` | Up to four capabilities drawn at random from all matching activities, unrelated to each other |
| `chain` | A complete scenario: up to four artifacts that describe one event and share a subject |

### LLMAttacker (attacker)

- **Threat Actor Profile.** One of eight profiles, each with a motivation, an attitude, and a risk tolerance, plus a skill level (`Beginner`, `Intermediate`, or `Advanced`). The skill level sets the size of the technique pool (6, 12, or 20), how often the attacker runs a reconnaissance sweep, and how patient it is.
- **Attack Planner.** A language model chooses the next technique from the pool and the follow-up commands to inspect new findings.
- **Actions on the Victim Machine.** It runs the Linux tests of [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for the chosen technique over SSH, one command at a time, and extracts new identifiers from each output.
- **Credibility Judge.** A language model scores how genuine each response looks.
- **Explicit rules decide when the attacker leaves:**
  - *Detection*: the attacker leaves after too many techniques with a suspicious response.
  - *Loss of interest*: the attacker leaves after too many rounds without new findings, unless the host has earned it extra patience. What earns patience depends on the skill level: any activity for a beginner, variety for an intermediate attacker, and findings that corroborate each other for an advanced one.

The attacker is never told which condition is active.

---

## Repository layout

```
src/honeyengage/      defender: sensor (SSH), telemetry, correlation_engine, engage_engine, virtual_env
src/llmattacker/      attacker: attack_engine, threat_actor, deception_engine (judge), interactor, atomics
src/evaluation/       engagement metrics and post-hoc credibility evaluation of recorded sessions
src/common/           timing helpers
orchestrator/         runs one defender-versus-attacker session; technique pools per skill level
scripts/              campaign runner, campaign configuration, Ollama container manager, dataset check
honeyfs/              files served by the emulated host (/etc, /proc, ...)
enterprise-attack.json, src/honeyengage/engage_engine/Engage-Data-V1.0.xlsx   pinned MITRE datasets (see DATASETS.md)
tests/                unit tests
```

---

## Requirements

- Linux, Python 3.11 or later.
- [Ollama](https://ollama.com), reached through its OpenAI-compatible endpoint (`http://localhost:11434/v1`).
- Docker, which the campaign runner uses to start Ollama in a container.
- A GPU is recommended. All models used in the paper have 7–8B parameters and run on a single workstation.

## Installation

```bash
git clone https://github.com/CyberDataLab/LLMHoney-Engage.git llmhoney-engage
cd llmhoney-engage
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-lock.txt   # exact versions used for the paper
# or: pip install -r requirements.txt
cp .env.example .env
python scripts/verify_datasets.py      # checks the pinned MITRE datasets
```

The SSH host key is created automatically at the path set in `HONEYENGAGE_RSA_KEY_FILE` the first time the honeypot starts.

---

## Running it

### 1. Honeypot only, attacked by hand

```bash
ollama pull llama3.1
# in .env: HONEYENGAGE_CORRELATION_MODEL=llama3.1, HONEYENGAGE_ENGAGE_MODEL=llama3.1
HONEYENGAGE_COA_MODE=chain HONEYENGAGE_PERSONA_MODE=random python -m src.honeyengage.honeyengage_main
```

Then connect from another terminal with any user name and password:

```bash
ssh -p 2222 user@localhost
```

Each session is saved to `data/<session_id>.json`, and every defender reaction is logged to `defend_metrics.jsonl`.

### 2. Honeypot against LLMAttacker

With the honeypot running, start the attacker in another terminal:

```bash
LLMATTACKER_LLM_MODEL=llama3.1 LLMATTACKER_LEVEL=Advanced \
LLMATTACKER_TECHNIQUES=T1082,T1033,T1552.001,T1053.003 ENABLE_METRICS=true \
python -m src.llmattacker.llmattacker_main
```

The attacker logs every command, judgement, and decision to `attack_metrics.jsonl`.

### 3. Full campaign

The campaign of the paper is defined in `scripts/campaign_config.yaml`:
- four models, each playing both roles;
- the four deception conditions;
- three skill levels;
- persona on and off;
- three repetitions.

That gives 1152 sessions.

```bash
python scripts/run_full_experiment_campaign.py --dry-run   # print the session matrix
python scripts/run_full_experiment_campaign.py             # run it
```

The runner works through one model pair at a time:
1. It starts an Ollama container and pulls the two models.
2. It runs every session of that pair one after another, each with its own seed.
3. It writes one row per session to `results/campaign_results.jsonl` and `results/campaign_results.csv`.

Every random choice comes from the session seed (persona, profile, technique pool, Atomic test, and capabilities), so any session can be reproduced.

---

## Configuration

The main environment variables are listed below; `.env.example` has the full list.

| Variable | Meaning |
|---|---|
| `OPENAI_BASE_URL`, `OPENAI_API_KEY` | OpenAI-compatible endpoint (Ollama: `http://localhost:11434/v1`, key `ollama`) |
| `HONEYENGAGE_PORT` | SSH port of the honeypot (default `2222`) |
| `HONEYENGAGE_CORRELATION_MODEL`, `HONEYENGAGE_ENGAGE_MODEL` | Models of the Technique Correlator and of the Engage Planner and Artifact Factory |
| `HONEYENGAGE_COA_MODE` | `static`, `same_ttp`, `multi_ttp`, or `chain` |
| `HONEYENGAGE_PERSONA_MODE` | `random` (draw a server role) or `none` (bare Ubuntu host) |
| `HONEYENGAGE_ENGAGE_ENGINE_THRESHOLD` | Minimum correlator confidence to react (paper: `0.6`) |
| `HONEYENGAGE_CORRELATION_ENGINE_TEMPERATURE`, `HONEYENGAGE_ENGAGE_ENGINE_TEMPERATURE` | Paper: `0.0` and `0.5` |
| `HONEYENGAGE_SEED` | Base seed of the defender |
| `LLMATTACKER_LLM_MODEL` | Model of the Attack Planner |
| `LLMATTACKER_JUDGE_MODEL` | Model of the Credibility Judge (paper: `llama3.1`) |
| `LLMATTACKER_LEVEL` | `Beginner`, `Intermediate`, or `Advanced` |
| `LLMATTACKER_TECHNIQUES` | Comma-separated technique pool |
| `LLMATTACKER_PROFILE` | Force one threat actor profile (otherwise drawn from the seed) |
| `LLMATTACKER_TEMPERATURE`, `LLMATTACKER_THRESHOLD` | Paper: `0.2`; a response is suspicious below `0.4` |
| `LLMATTACKER_SEED` | Base seed of the attacker |

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/
```

---

## Third-party content

- **MITRE ATT&CK** (`enterprise-attack.json`) and **MITRE Engage** (`Engage-Data-V1.0.xlsx`), © The MITRE Corporation, used under their terms of use. The exact versions are pinned in `DATASETS.md`.
- **Atomic Red Team** test definitions (`src/llmattacker/atomics`), © Red Canary, MIT License.
- **Cowrie** command implementations (`src/honeyengage/virtual_env/cowrie`, `src/honeyengage/virtual_env/commands`), BSD-3-Clause. Their original copyright notices are kept in each file.

## Citation

If you use this code, please cite the accompanying paper:

```bibtex
@article{beltranlopez2026narrative,
  title   = {Adaptive LLM-Driven Honeypots vs. LLM-Driven Attackers: Does Narrative Coherence Improve Deception?},
  author  = {Beltr{\'a}n-L{\'o}pez, Pedro and Gonzalez Jimenez, Raul and Gil P{\'e}rez, Manuel and Nespoli, Pantaleone},
  year    = {2026},
  note    = {Under review}
}
```

## License

The code of this repository is released under the [MIT License](LICENSE). Third-party content keeps its own license, as listed above.

## Responsible use

This software is intended for defensive research. The honeypot accepts any credentials and records everything typed into it, so deploy it only on infrastructure you own, and inform users where required. The attacker runs only against the emulated host it is pointed at; do not point it at systems you are not authorised to test.
