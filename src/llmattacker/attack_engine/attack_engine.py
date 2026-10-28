"""Attack loop of LLMAttacker: runs each chosen technique over SSH, extracts discoveries, and applies the detection and loss-of-interest rules that decide when the attacker leaves."""

import json
import os
import re
import time
from datetime import UTC, datetime

import paramiko
import yaml
from dotenv import load_dotenv
from loguru import logger
from numpy import random
from openai import OpenAI

from src.llmattacker.deception_engine.credibility_analyzer import CredibilityAnalyzer
from src.llmattacker.interactor.interactor import Interactor
from src.llmattacker.threat_actor.attack_planner import AttackPlanner, TechniqueOutcome
from src.llmattacker.threat_actor.profile import pick_threat_actor_profile

load_dotenv()

logger.add("logs/attack_engine.log", rotation="1 day")

class AttackEngine:
  RECON_INTERVAL_BY_LEVEL = {"Advanced": 1, "Intermediate": 2, "Beginner": 3}

  VARIETY_CREDULITY_BY_LEVEL = {"Advanced": 0.34, "Intermediate": 0.67, "Beginner": 1.0}

  MEANINGFUL_NOVELTY_TOKENS = 5


  COHERENCE_ACUITY_BY_LEVEL = {"Advanced": 2.5, "Intermediate": 1.5, "Beginner": 1.0}

  def __init__(self, atomics_path: str, interactor: Interactor, enable_metrics: bool, metrics_file: str = "attack_metrics.jsonl"):
    self.interactor = interactor
    self.atomics_path = atomics_path
    self.analyzer = CredibilityAnalyzer()
    self.enable_metrics = enable_metrics
    self.metrics_file = metrics_file
    self.level = os.getenv("LLMATTACKER_LEVEL", "Beginner")
    self.techniques = os.getenv("LLMATTACKER_TECHNIQUES", "").split(",") if os.getenv("LLMATTACKER_TECHNIQUES") else []
    self.bonus_techniques = os.getenv("LLMATTACKER_BONUS_TECHNIQUES", "").split(",") if os.getenv("LLMATTACKER_BONUS_TECHNIQUES") else []
    logger.info(f"Techniques to execute: {self.techniques}")
    if self.bonus_techniques:
      logger.info(f"Bonus techniques in reserve (planner may request one): {self.bonus_techniques}")
    self.oracle_client: paramiko.SSHClient | None = None
    self._connect_oracle()

    seed_val = os.getenv("LLMATTACKER_SEED")
    if seed_val is not None:
        random.seed(int(seed_val))

    self.profile = pick_threat_actor_profile(
      session_id=str(os.getenv("LLMATTACKER_PROFILE_SEED_KEY") or os.getenv("SESSION_ID", "default_session")),
      forced_profile_id=os.getenv("LLMATTACKER_PROFILE"),
      base_seed=seed_val,
    )
    logger.info(f"Playing threat actor profile: {self.profile.profile_id} ({self.profile.profile}/{self.profile.motivation}/{self.profile.attitude})")

    planner_llm_client = OpenAI(
      base_url=os.getenv("OPENAI_BASE_URL"),
      api_key=os.getenv("OPENAI_API_KEY", "dummy-key"),
    )
    self.planner = AttackPlanner(llm_client=planner_llm_client, profile=self.profile)
    self._baseline_system_tokens = self._load_baseline_system_tokens()

  def _load_baseline_system_tokens(self) -> set[str]:
    tokens: set[str] = set()
    for rel_path in ("etc/passwd", "etc/group", "etc/shadow"):
      path = os.path.join("honeyfs", rel_path)
      if not os.path.exists(path):
        continue
      try:
        with open(path, encoding="utf-8") as f:
          content = f.read()
        tokens.update(tok.lower() for tok in re.findall(r"/[\w./-]{3,}|\b[\w][\w.-]{2,}\b", content))
      except OSError as e:
        logger.warning(f"Could not load baseline system tokens from {path}: {e}")

    tokens.update(tok.lower() for tok in re.findall(
      r"/[\w./-]{3,}|\b[\w][\w.-]{2,}\b",
      "/bin/bash /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin xterm-256color en_US.UTF-8 /home/user "
      "bootstrap.log wtmp faillog btmp lastlog alternatives.log apt dpkg.log "
      "0 loaded units listed.",
    ))

    try:
      from src.honeyengage.virtual_env.machine_persona import MACHINE_ROLES, NEUTRAL_ROLE

      persona_terms: list[str] = []
      for persona in [NEUTRAL_ROLE, *MACHINE_ROLES.values()]:
        for _port, service_name in getattr(persona, "typical_ports", []):
          persona_terms.append(f"{service_name} {service_name}.service systemd-{service_name}.service")
        for package_name, _version, _description in getattr(persona, "typical_packages", []):
          persona_terms.append(package_name)
      tokens.update(tok.lower() for tok in re.findall(
        r"/[\w./-]{3,}|\b[\w][\w.-]{2,}\b", " ".join(persona_terms),
      ))
    except Exception as exc:  # pragma: no cover - defensive, never fatal
      logger.warning(f"Could not load machine persona baseline tokens: {exc}")

    return tokens

  def _is_linux_supported(self, test: dict) -> bool:
    supported_platforms = [platform.lower() for platform in test.get("supported_platforms", [])]
    return not supported_platforms or "linux" in supported_platforms

  def _connect_oracle(self) -> bool:
    oracle_host = os.getenv("ORACLE_HOST")
    
    if not oracle_host:
      logger.info("ORACLE_HOST not defined. Oracle Differential Testing is disabled.")
      return False
      
    try:
      self.oracle_client = paramiko.SSHClient()
      self.oracle_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      
      self.oracle_client.connect(
        hostname=oracle_host,
        port=int(os.getenv("ORACLE_PORT", 22)),
        username=os.getenv("ORACLE_USER", "ubuntu"),
        password=os.getenv("ORACLE_PASS", "ubuntu"),
        timeout=10
      )
      logger.success(f"Connected to Oracle VM at {oracle_host}")
      return True
      
    except Exception as e:
      logger.warning(f"Failed to connect to Oracle VM: {e}")
      self.oracle_client = None
      return False

  def _get_oracle_output(self, command: str) -> str:
    if not self.oracle_client:
      logger.warning("Oracle client not connected. Skipping oracle output retrieval.")
      return "ORACLE_NOT_CONNECTED"
      
    try:
      stdin, stdout, stderr = self.oracle_client.exec_command(command, timeout=15)
      
      out = stdout.read().decode('utf-8', errors='ignore')
      err = stderr.read().decode('utf-8', errors='ignore')
      
      return (out + err).strip()
    except Exception as e:
      logger.error(f"Error executing command on Oracle VM: {e}")
      return "ORACLE_TIMEOUT_OR_ERROR"
  
  def _should_abandon_as_honeypot(self, history: list[TechniqueOutcome]) -> bool:
    """Detection rule: leave when the number of suspicious techniques reaches max(2, round(psi * delta)), where psi is the suspicion tolerance of the profile and delta the scaling of the skill level."""
    suspicious = sum(1 for h in history if h.honeypot_detected)
    if suspicious == 0:
      return False

    patience_by_attitude = {
      "Opportunistic": 1,
      "Destructive": 2,
      "Targeted": 3,
      "Persistent": 3,
    }
    patience = patience_by_attitude.get(self.profile.attitude, 2)
    if self.profile.risk_level >= 7:
      patience += 1

    detection_skill_multiplier = {"Beginner": 1.5, "Intermediate": 1.0, "Advanced": 0.85}.get(self.level, 1.0)
    threshold = max(2, round(patience * detection_skill_multiplier))

    return suspicious >= threshold

  def _should_abandon_as_uninteresting(self, history: list[TechniqueOutcome]) -> bool:
    """Loss-of-interest rule: leave when the weighted streak of unproductive rounds reaches the base patience of the level plus the extra patience earned so far (capped at 12)."""
    base_threshold = self.RECON_INTERVAL_BY_LEVEL.get(self.level, 2)

    if len(history) < base_threshold:
      return False

    def technique_family(technique_id: str) -> str:
      return technique_id.split(".")[0]

    streak = 0.0
    previous_family: str | None = None
    for outcome in reversed(history):
      if outcome.new_notable_tokens >= self.MEANINGFUL_NOVELTY_TOKENS:
        break
      family = technique_family(outcome.technique_id)
      streak += 2.0 if family == previous_family else 1.0
      previous_family = family

    CORROBORATION_STEP = 3
    MAX_EARNED_BONUS = 12
    distinct_classes: set[str] = set()
    for outcome in history:
      distinct_classes |= outcome.new_artifact_classes
    breadth = len(distinct_classes)
    reactive_rounds = sum(1 for outcome in history if outcome.new_artifact_classes)
    productive_rounds = sum(
      1 for outcome in history if outcome.new_notable_tokens >= self.MEANINGFUL_NOVELTY_TOKENS
    )
    corroboration = sum(outcome.corroborated_tokens for outcome in history)

    if self.level == "Beginner":
      earned_bonus = min(MAX_EARNED_BONUS, 4 * min(reactive_rounds, 2) + reactive_rounds)
    elif self.level == "Intermediate":
      breadth_score = min(breadth, 4) + (breadth - 4) // 2 if breadth > 4 else breadth
      earned_bonus = min(MAX_EARNED_BONUS, breadth_score + productive_rounds // 2)
    else:
      earned_bonus = min(
        MAX_EARNED_BONUS,
        (corroboration // CORROBORATION_STEP) * 2 + min(breadth, 3),
      )

    boredom_threshold = base_threshold + earned_bonus

    return streak >= boredom_threshold

  _ARTIFACT_CLASS_PATTERNS: tuple[tuple[str, str], ...] = (
    ("log", r"(^|/)var/log/|\.log(\.\d+)?$|\.log\b|oplog|journal|audit|syslog|access[-_]|error[-_]"),
    ("credential", r"aws|credential|secret|token|\.pem$|id_rsa|authorized_keys|password|passwd\b|\.ldif$|\.key$|apikey|\bkey-|[0-9a-f]{16,}"),
    ("account", r"(^|/)home/|/etc/passwd|/etc/shadow|useradd|\buid=|\bgid=|\buser[-_]|admin"),
    ("network", r"\b(eth|ens|enp|docker|br-|veth|tun|wlan)\d|inet\b|(^|/)etc/hosts|\.sock$|:\d{2,5}\b|haproxy|squid|\bproxy[-_.]|cluster[-_.]"),
    ("process", r"\.service\b|systemd|daemon|/proc/|\.pid$|(^|/)run/|pid[-_]file|[-_]state$"),
    ("package", r"\.deb$|dpkg|apt\b|/usr/(bin|sbin|lib)/|\.rpm$|nginx|apache|mysql|postgres|mongodb|redis|elasticsearch|docker|php|python|java"),
    ("history", r"bash_history|\.bashrc$|\.profile$|\.ssh/|dotfile|\.config|\.cache"),
    ("tempfile", r"(^|/)tmp/|\.tmp$|\.swp$|\.bak$|(^|/)var/tmp/|temp|tmp[-_]"),
    ("backup", r"backup|\.gz$|\.tar$|\.zip$|\.sql$|dump|snapshot|archive"),
    ("config", r"\.conf$|\.cfg$|\.ini$|\.ya?ml$|\.json$|(^|/)etc/|config[-_./]"),
  )

  def _count_corroborated_tokens(self, tokens: set[str], seen_tokens: set[str], result: str) -> int:
    if not tokens:
      return 0

    def stem_of(token: str) -> str:
      stem = token.rstrip("/").split("/")[-1]
      return re.sub(r"\.(log|conf|cfg|service|sock|pid|txt|sh|py|gz|tar|json|ya?ml)(\.\d+)?$", "", stem)

    def normalise(token: str) -> str:
      return re.sub(r"\.\d+$", "", token)

    by_stem: dict[str, set[str]] = {}
    for token in tokens | seen_tokens:
      stem = stem_of(token)
      if len(stem) < 5:
        continue
      by_stem.setdefault(stem, set()).add(normalise(token))

    corroborated = 0
    for token in tokens:
      stem = stem_of(token)
      if len(stem) < 5:
        continue
      if len(by_stem.get(stem, set())) >= 2:
        corroborated += 1
    return corroborated

  def _classify_artifact_tokens(self, tokens: set[str]) -> set[str]:
    classes: set[str] = set()
    for token in tokens:
      matched = False
      for class_name, pattern in self._ARTIFACT_CLASS_PATTERNS:
        if re.search(pattern, token):
          classes.add(class_name)
          matched = True
      if not matched:
        classes.add("other")
    return classes

  def add_arguments_to_commands(self, commands: str, input_args: dict) -> str:
    for arg_name, arg_details in input_args.items():
      default_value = arg_details.get("default", "")
      placeholder = f"#{{{arg_name}}}"
      commands = commands.replace(placeholder, str(default_value))
    return commands

  def _capture_session_baseline(self) -> set[str]:
    baseline: set[str] = set()
    for command in self.planner.PERIODIC_RECON_COMMANDS:
      try:
        output = self.interactor.execute_command(command)
      except Exception as exc:
        logger.warning(f"Baseline sweep command {command!r} failed: {exc}")
        continue
      if output:
        baseline |= self._extract_notable_tokens(output, command)
    logger.info(f"Captured {len(baseline)} baseline tokens before any technique ran.")
    return baseline

  def run_simulation(self, session_id: str):
    logger.info(f"--- Starting Session: {session_id} ---")

    if not self.interactor.connect():
      logger.error("Failed to connect to target. Aborting simulation.")
      return

    start_time = time.time()
    total_commands = 0
    credibility_scores = []
    honeypot_detected = False
    executed_techniques = []
    history: list[TechniqueOutcome] = []
    seen_notable_tokens: set[str] = self._capture_session_baseline()
    self_authored_tokens: set[str] = set()
    techniques_since_recon = 0

    abandoned_as_honeypot = False
    abandoned_as_uninteresting = False
    remaining = list(self.techniques)
    bonus_used = 0

    try:
      bonus_remaining = list(self.bonus_techniques)
      max_bonus_per_session = len(bonus_remaining)

      while remaining or bonus_remaining:
        bonus_available = bool(bonus_remaining) and bonus_used < max_bonus_per_session
        decision = self.planner.decide_next_step(remaining, history, bonus_available=bonus_available)

        if decision.next_technique_id is None:
          if decision.request_bonus_technique and bonus_available:
            technique_id = bonus_remaining.pop(0)
            bonus_used += 1
            logger.info(f"Attack planner requested a bonus technique: {technique_id} (reasoning: {decision.reasoning})")
          else:
            logger.info(f"Attack planner decided to stop the session: {decision.reasoning}")
            break
        else:
          technique_id = decision.next_technique_id
          remaining.remove(technique_id)

        executed_techniques.append(technique_id)
        logger.info(f"Executing technique: {technique_id} (planner reasoning: {decision.reasoning})")

        honeypot_detected_in_technique, cmds_run, scores, technique_tokens, result_text = self.execute_technique(
          session_id, technique_id, self_authored_tokens
        )
        total_commands += cmds_run
        credibility_scores.extend(scores)
        if honeypot_detected_in_technique:
          honeypot_detected = True

        technique_tokens -= self_authored_tokens
        new_tokens = technique_tokens - seen_notable_tokens
        seen_notable_tokens |= technique_tokens

        if not honeypot_detected_in_technique:
          followup_commands = self.planner.decide_followup_commands(technique_id, result_text, len(new_tokens))
          for command in followup_commands:
            oracle_output = self._get_oracle_output(command)
            output = self.interactor.execute_command(command)
            total_commands += 1
            cmds_run += 1
            followup_tokens = self._extract_notable_tokens(output, command) - self_authored_tokens
            if followup_tokens:
              logger.debug(f"[novelty-debug-followup] command={command!r} contributed={followup_tokens}")
            self_authored_tokens |= self._extract_command_tokens(command)
            new_tokens |= followup_tokens - seen_notable_tokens
            seen_notable_tokens |= followup_tokens

            evaluation_result = self.analyzer.analyze_response(command, output, oracle_output)
            scores.append(evaluation_result.score)
            credibility_scores.append(evaluation_result.score)
            logger.info(
              f"Follow-up command: {command}\nOutput: {output}\n"
              f"Credibility Score: {evaluation_result.score:.2f}\nReasoning: {evaluation_result.reasoning}"
            )
            if evaluation_result.score < self.analyzer.threshold:
              logger.warning(f"Low credibility score for follow-up command: {command}.")
              honeypot_detected_in_technique = True
              honeypot_detected = True

            metrics_data = {
              "timestamp": datetime.now(UTC).isoformat(),
              "session_id": session_id,
              "llm_model": self.analyzer.model,
              "event_type": "command",
              "command_executed": command,
              "attacker_level": self.level,
              "technique": technique_id,
              "error": evaluation_result.error,
              "credibility_score": round(evaluation_result.score, 3),
              "reasoning": evaluation_result.reasoning,
              "detected_honeypot": honeypot_detected_in_technique,
              "is_followup": True,
            }
            with open(self.metrics_file, "a", encoding="utf-8") as f:
              f.write(json.dumps(metrics_data) + "\n")

        if cmds_run == 0:
          logger.info(f"Technique {technique_id} produced no executable commands; not counted toward abandonment history.")
          continue

        techniques_since_recon += 1

        if not honeypot_detected_in_technique:
          recon_interval = self.RECON_INTERVAL_BY_LEVEL.get(self.level, 2)
          recon_commands = self.planner.decide_periodic_recon_commands(techniques_since_recon, recon_interval)
          for command in recon_commands:
            oracle_output = self._get_oracle_output(command)
            output = self.interactor.execute_command(command)
            total_commands += 1
            recon_tokens = self._extract_notable_tokens(output, command) - self_authored_tokens
            if recon_tokens:
              logger.debug(f"[novelty-debug-recon] command={command!r} contributed={recon_tokens}")
            self_authored_tokens |= self._extract_command_tokens(command)
            new_tokens |= recon_tokens - seen_notable_tokens
            seen_notable_tokens |= recon_tokens

            evaluation_result = self.analyzer.analyze_response(command, output, oracle_output)
            credibility_scores.append(evaluation_result.score)
            logger.info(
              f"Periodic recon command: {command}\nOutput: {output}\n"
              f"Credibility Score: {evaluation_result.score:.2f}\nReasoning: {evaluation_result.reasoning}"
            )
            if evaluation_result.score < self.analyzer.threshold:
              logger.warning(f"Low credibility score for periodic recon command: {command}.")
              honeypot_detected = True

            metrics_data = {
              "timestamp": datetime.now(UTC).isoformat(),
              "session_id": session_id,
              "llm_model": self.analyzer.model,
              "event_type": "command",
              "command_executed": command,
              "attacker_level": self.level,
              "technique": technique_id,
              "error": evaluation_result.error,
              "credibility_score": round(evaluation_result.score, 3),
              "reasoning": evaluation_result.reasoning,
              "detected_honeypot": evaluation_result.score < self.analyzer.threshold,
              "is_periodic_recon": True,
            }
            with open(self.metrics_file, "a", encoding="utf-8") as f:
              f.write(json.dumps(metrics_data) + "\n")

          if recon_commands:
            techniques_since_recon = 0

        new_classes = self._classify_artifact_tokens(new_tokens)
        corroborated = self._count_corroborated_tokens(
          new_tokens, seen_notable_tokens - new_tokens, result_text
        )
        if new_tokens:
          logger.debug(f"[novelty-debug] technique={technique_id} new_tokens={new_tokens}")
          logger.debug(
            f"[novelty-debug-classes] technique={technique_id} "
            f"classes={sorted(new_classes)} corroborated={corroborated}"
          )
        technique_avg = sum(scores) / len(scores) if scores else 1.0
        history.append(TechniqueOutcome(
          technique_id=technique_id,
          commands_executed=cmds_run,
          honeypot_detected=honeypot_detected_in_technique,
          avg_credibility=technique_avg,
          new_notable_tokens=len(new_tokens),
          new_artifact_classes=frozenset(new_classes),
          corroborated_tokens=corroborated,
        ))

        if self._should_abandon_as_honeypot(history):
          logger.info(
            f"Attacker concluded the target is a honeypot and abandoned the session "
            f"(profile={self.profile.profile_id}, attitude={self.profile.attitude}, "
            f"risk_level={self.profile.risk_level})"
          )
          abandoned_as_honeypot = True
          break

        if self._should_abandon_as_uninteresting(history):
          logger.info(
            f"Attacker lost interest -- the target never showed anything worth the effort -- "
            f"and abandoned the session (profile={self.profile.profile_id}, attitude={self.profile.attitude})"
          )
          abandoned_as_uninteresting = True
          break

    except Exception as e:
      logger.error(f"Error during simulation: {e}")

    finally:
      self.interactor.disconnect()

      time_elapsed = round(time.time() - start_time, 2)
      avg_credibility = sum(credibility_scores) / len(credibility_scores) if credibility_scores else 0.0

      metrics_data = {
        "timestamp": datetime.now(UTC).isoformat(),
        "session_id": session_id,
        "llm_model": self.analyzer.model,
        "event_type": "attack_simulation",
        "attacker_level": self.level,
        "threat_actor_profile": self.profile.profile_id,
        "total_commands": total_commands,
        "time_elapsed_sec": time_elapsed,
        "detected_honeypot": honeypot_detected,
        "abandoned_as_honeypot": abandoned_as_honeypot,
        "abandoned_as_uninteresting": abandoned_as_uninteresting,
        "techniques_attempted_before_abandoning": (
          len(executed_techniques) if (abandoned_as_honeypot or abandoned_as_uninteresting) else None
        ),
        "techniques": executed_techniques,
        "assigned_pool_size": len(self.techniques),
        "assigned_pool_exhausted": len(remaining) == 0,
        "bonus_techniques_used": bonus_used,
        "avg_credibility": round(avg_credibility, 3)
      }

      with open(self.metrics_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics_data) + "\n")

      logger.info("Attack simulation completed and disconnected from target.")

  def execute_technique(
    self, session_id: str, technique_id: str, self_authored_tokens: set[str] | None = None
  ) -> tuple[bool, int, list, set, str]:
    if self_authored_tokens is None:
      self_authored_tokens = set()
    technique_path = os.path.join(self.atomics_path, technique_id, f"{technique_id}.yaml")

    if not os.path.exists(technique_path):
      logger.error(f"YAML file not found for technique: {technique_id}")
      return False, 0, [], set(), ""

    try:
      with open(technique_path, encoding="utf-8") as f:
        technique_data = yaml.safe_load(f)
    except Exception as e:
      logger.error(f"Failed to load technique {technique_id}: {e}")
      return False, 0, [], set(), ""

    atomic_tests = technique_data.get("atomic_tests", [])

    commands_executed = 0
    credibility_scores = []
    technique_honeypot_detected = False
    notable_tokens: set[str] = set()
    result_texts: list[str] = []

    atomic_tests = [test for test in atomic_tests if self._is_linux_supported(test)]

    if os.getenv("LLMATTACKER_SELECT_RANDOM_TEST", "false").lower() == "true":
      test = random.choice(atomic_tests) if atomic_tests else None
      atomic_tests = [test] if test else []
    
    for test in atomic_tests:
      executor = test.get("executor", {})
      raw_commands = executor.get("command")

      if not raw_commands:
        continue

      input_args = test.get("input_arguments", {})
      raw_commands = self.add_arguments_to_commands(raw_commands, input_args)

      test_honeypot_detected = False

      joined_commands = re.sub(r"\\\s*\n\s*", " ", raw_commands)
      for command in joined_commands.split("\n"):
        command = command.strip()
        if not command or command.startswith("#"):
          continue

        first_token = command.split()[0].lower() if command.split() else ""
        if first_token in {"exit", "logout", "poweroff", "reboot", "shutdown", "halt"}:
          logger.info(f"Skipping session-terminating command from atomic test: {command!r}")
          continue

        oracle_output = self._get_oracle_output(command)

        output = self.interactor.execute_command(command)
        commands_executed += 1
        _cmd_tokens = self._extract_notable_tokens(output, command)
        if _cmd_tokens:
          logger.debug(f"[novelty-debug-cmd] command={command!r} contributed={_cmd_tokens}")
        notable_tokens |= _cmd_tokens
        self_authored_tokens |= self._extract_command_tokens(command)
        result_texts.append(f"$ {command}\n{output}")

        evaluation_result = self.analyzer.analyze_response(command, output, oracle_output)
        credibility_scores.append(evaluation_result.score)

        logger.info(f"Command: {command}\nOutput: {output}\nCredibility Score: {evaluation_result.score:.2f}\nReasoning: {evaluation_result.reasoning}")

        if evaluation_result.score < self.analyzer.threshold:
          logger.warning(f"Low credibility score for command: {command}. Output may not be consistent with a real Linux system.")
          test_honeypot_detected = True
          technique_honeypot_detected = True
        
        metrics_data = {
          "timestamp": datetime.now(UTC).isoformat(),
          "session_id": session_id,
          "llm_model": self.analyzer.model,
          "event_type": "command",
          "command_executed": command,
          "attacker_level": self.level,
          "technique": technique_id,
          "error": evaluation_result.error,
          "credibility_score": round(evaluation_result.score, 3),
          "reasoning": evaluation_result.reasoning,
          "detected_honeypot": test_honeypot_detected,
        }

        with open(self.metrics_file, "a", encoding="utf-8") as f:
          f.write(json.dumps(metrics_data) + "\n")

        if test_honeypot_detected:
          break
      
      cleanup_commands = executor.get("cleanup_command")

      if not cleanup_commands:
        continue

      input_args = test.get("input_arguments", {})
      cleanup_commands = self.add_arguments_to_commands(cleanup_commands, input_args)

      for command in cleanup_commands.split("\n"):
        command = command.strip()
        if not command or command.startswith("#"):
          continue
        self._get_oracle_output(command)
    return technique_honeypot_detected, commands_executed, credibility_scores, notable_tokens, "\n".join(result_texts)

  def _extract_command_tokens(self, command: str) -> set[str]:
    tokens = {tok.lower() for tok in re.findall(r"[\w./-]+", command)}
    for tok in list(tokens):
      if tok.startswith("-"):
        tokens.add(tok.lstrip("-"))
      if "/" not in tok:
        continue
      parts = tok.split("/")
      for i in range(1, len(parts)):
        suffix = "/".join(parts[i:])
        tokens.add(suffix)
        tokens.add("/" + suffix)
    return tokens

  def _extract_notable_tokens(self, output: str, command: str) -> set[str]:
    if not output:
      return set()
    result = output
    if result.startswith(command):
      result = result[len(command):]
    result = re.sub(r"[^\n]*[$#]\s*$", "", result)
    if not result.strip():
      return set()
    candidates = {tok.lower() for tok in re.findall(r"/[\w./-]{3,}|\b[\w][\w.-]{2,}\b", result)}
    command_tokens = self._extract_command_tokens(command)
    return {
      tok for tok in candidates
      if tok.lower() not in self._GENERIC_SHELL_VOCABULARY
      and tok.lower() not in self._baseline_system_tokens
      and tok.lower() not in command_tokens
      and not tok.strip("/").replace(".", "").replace("-", "").isdigit()
      and not re.search(r"\d{5,}", tok)
      and not (tok.endswith(".bash_history") and "no such file or directory" in result.lower())
      and not re.fullmatch(r"(\d+(\.\d+)?[smhd])+", tok)
      and not re.fullmatch(r"\d{4}-\d{2}-\d{2}t\d{2}", tok)
      and not re.fullmatch(r"\d{2}z", tok)
      and not tok.endswith(".service")
      and not tok.endswith(".socket")
      and not tok.endswith(".timer")
      and not tok.endswith(".mount")
    }

  _GENERIC_SHELL_VOCABULARY = frozenset({
    "user", "pid", "cpu", "mem", "tty", "stat", "start", "time", "cmd",
    "vsz", "rss", "uid", "gid", "from", "login", "idle", "what",
    "bash", "sh", "command", "not", "found", "no", "such", "file",
    "directory", "permission", "denied", "cannot", "access", "error",
    "internal", "usage", "invalid", "option", "unrecognized", "missing",
    "operand", "syntax", "unexpected", "line", "proto", "recv",
    "send", "local", "address", "foreign", "state", "listen",
    "send-q", "recv-q", "netid", "peer", "iface", "destination",
    "gateway", "genmask", "flags", "metric", "ref", "use",
    "unit", "running", "scope", "systemd-run", "argument",
    "status", "active", "inactive", "description", "loaded", "enabled",
    "disabled", "exited", "dead", "since", "main", "tasks", "memory",
    "cgroup", "sub", "default", "exists", "created_at", "table", "update",
    "pathtoatomicsfolder",
    "unknown", "executable", "could", "be", "doctype", "html", "head", "body", "title", "meta",
    "statistics", "transmitted", "received", "packets", "packet", "loss",
    "rtt", "min", "avg", "max", "mdev", "/avg/max/mdev", "icmp_seq", "ttl",
    "bytes", "adding",
    "/title", "/head", "/body", "/html", "/meta",
    "path", "pwd", "shell", "lang", "term", "logname", "home",
    "job", "mon", "tue", "wed", "thu", "fri", "sat", "sun",
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    "pts", "tty1", "tty2", "tty3", "tty4", "tcp", "udp", "init", "/sbin/init",
    "near", "token", "fi",
    "ascii", "text", "bashrc", "profile", "bash.bashrc", "/etc/bash.bashrc",
    "/root/.bashrc", "/root/.profile",
    "skipping", "machine",
    "established",
    "out", "copied", "records",
    "days", "average", "x86_64", "gnu", "6.8.0-49-generic", "ubuntu",
    "smp", "linux", "load", "/linux", "49-ubuntu", "groups", "jcpu",
    "pcpu", "0.00s", "1.00s", "0.02s",
    "open",
    "/usr/bin/python3", "/bin/bash", "/bin/sh", "/usr/bin/curl",
    "/usr/bin/wget", "/usr/bin/perl", "/usr/bin/awk", "/bin/grep",
    "/bin/sed", "/bin/systemctl", "/usr/sbin/cron", "/usr/bin/crontab",
    "/usr/bin/ssh", "/usr/bin/scp", "/bin/nc",
  })