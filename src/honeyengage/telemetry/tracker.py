"""Per-session state of the defender: command history, technique correlation, Engage reactions, and metrics."""

import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger
from pydantic import ValidationError

from src.honeyengage.correlation_engine.mitre_mapper import MitreMapper
from src.honeyengage.engage_engine.engage_engine import EngageEngine
from src.honeyengage.engage_engine.engage_parser import EngageParser
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell

from .models import (
  AuthenticationInfo,
  EnvironmentInfo,
  InteractionInfo,
  MitreMapping,
  MitreMappingError,
  NetworkInfo,
  Session,
  SessionInfo,
)

DEFAULT_ENGAGE_CONFIDENCE_THRESHOLD = 0.6

logger.add("logs/honeyengage_tracker.log", rotation="10 MB")

_MITRE_ANALYSIS_CONCURRENCY = int(os.getenv("HONEYENGAGE_MITRE_ANALYSIS_CONCURRENCY", "2"))
_mitre_analysis_semaphore = threading.Semaphore(_MITRE_ANALYSIS_CONCURRENCY)

_PERIODIC_RECON_COMMANDS = frozenset({
  "ps aux", "netstat -tulpn", "who", "cat /etc/passwd",
  "ls -la /var/log/", "ls -la /tmp/", "ls -la ~",
  "systemctl --failed", "cat ~/.bash_history",
})

class SessionTracker:
  def __init__(
    self, 
    session_id: str, 
    source_ip: str, 
    source_port: int, 
    client_version: str,
    llm_client,
    engage_parser: EngageParser,
    engage_engine: EngageEngine
  ):
    self.session_id = session_id
    self.start_time = datetime.now(UTC)

    self.network_info = NetworkInfo(
      source_ip=source_ip,
      source_port=source_port,
      ssh_client=client_version
    )
    self.env_info: EnvironmentInfo | None = None
    self.auth_info: AuthenticationInfo | None = None
    self.interactions: list[InteractionInfo] = []
    self.attack_data = self._load_attack_data()
    self.mitre_mapper = MitreMapper(llm_client, os.getenv("HONEYENGAGE_CORRELATION_MODEL", "llama3.1"), list(self.attack_data.keys()))
    self.mitre_mapping: list[MitreMapping] = []
    self.analysis_threads: list[threading.Thread] = []
    self.engage_parser = engage_parser
    self.engage_engine = engage_engine
    self.vfs: VirtualFileSystem | None = None
    self.virtual_shell: VirtualShell | None = None
    self.enable_metrics = os.getenv("ENABLE_METRICS", "false").lower() == "true"
    if self.enable_metrics:
      self.metrics_file = os.getenv("METRICS_FILE", "defend_metrics.jsonl")
    self.engage_engine_confidence_threshold = float(os.getenv("HONEYENGAGE_ENGAGE_ENGINE_THRESHOLD", DEFAULT_ENGAGE_CONFIDENCE_THRESHOLD))

  def _load_attack_data(self) -> dict[str, str]:
    attack_file = Path("enterprise-attack.json")
    if not attack_file.exists():
      logger.warning(f"ATT&CK data file not found: {attack_file}")
      return {}

    try:
      with attack_file.open("r", encoding="utf-8") as file_handle:
        bundle = json.load(file_handle)
    except Exception as exc:
      logger.error(f"Failed to load ATT&CK data from {attack_file}: {exc}")
      return {}

    attack_map: dict[str, str] = {}
    for obj in bundle.get("objects", []):
      if obj.get("type") != "attack-pattern":
        continue

      external_refs = obj.get("external_references", [])
      attack_id = None
      for reference in external_refs:
        if reference.get("source_name") == "mitre-attack":
          attack_id = reference.get("external_id")
          break

      if not attack_id:
        continue

      description = obj.get("description", "No description available.")
      attack_map[str(attack_id)] = str(description)

    return attack_map

  def add_ssh_client(self, client_version: str):
    self.network_info.ssh_client = client_version

  def set_session_environment(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell):
    self.vfs = vfs
    self.virtual_shell = virtual_shell

  def add_authentication(self, username: str, password: str):
    self.auth_info = AuthenticationInfo(
      username=username,
      password=password,
      timestamp=datetime.now(UTC)
    )
  
  def add_environment(self, terminal_type: str, shell_width: int, shell_height: int):
    self.env_info = EnvironmentInfo(
      terminal_type=terminal_type,
      shell_width=shell_width,
      shell_height=shell_height
    )

  def _summarize_observed_attacker_behavior(self) -> str:
    if len(self.interactions) < 2:
      return "First command of the session; no behavioral pattern observed yet."

    completed = [i for i in self.interactions if i.response is not None]
    if len(completed) < 2:
      return "Too few completed commands yet to characterize pace or pattern."

    timestamps = [i.timestamp for i in completed]
    gaps = [(t2 - t1).total_seconds() for t1, t2 in zip(timestamps, timestamps[1:], strict=False)]
    avg_gap = sum(gaps) / len(gaps) if gaps else 0.0
    if avg_gap < 2:
      pace = "very fast (near-automated, little apparent deliberation between commands)"
    elif avg_gap < 8:
      pace = "moderate"
    else:
      pace = "slow/deliberate (long pauses between commands)"

    techniques_seen = [i.mitre_mapping.technique_id for i in completed if i.mitre_mapping]
    unique_techniques = len(set(techniques_seen))
    variety = (
      "exploring many different techniques" if unique_techniques >= 4
      else "repeating/focused on a narrow set of techniques" if techniques_seen
      else "no techniques confidently identified yet"
    )

    low_cred_count = sum(
      1 for i in completed
      if i.engage_details and i.engage_details.result_status not in ("success", "unsupported_capability")
    )

    return (
      f"{len(completed)} commands so far, avg {avg_gap:.1f}s apart ({pace}). "
      f"{unique_techniques} distinct ATT&CK technique(s) observed, {variety}. "
      f"{low_cred_count} prior engagement attempt(s) this session did not land cleanly."
    )

  def add_interaction(self, command: str, backspaces: int) -> tuple[InteractionInfo, threading.Thread | None]:
    interaction = InteractionInfo(
      command=command,
      timestamp=datetime.now(UTC),
      backspaces=backspaces,
      response=None,
      mitre_mapping=None,
      engage_details=None,
      response_latency_seconds=None,
    )

    self.interactions.append(interaction)

    previous_thread = self.analysis_threads[-1] if self.analysis_threads else None

    def background_analisis(command: str, target_interaction: InteractionInfo):
      if previous_thread is not None:
        previous_thread.join()
      with _mitre_analysis_semaphore:
        _run_background_analysis(command, target_interaction)

    def _run_background_analysis(command: str, target_interaction: InteractionInfo):
      try:
        start_time = time.time()

        mitre_result = self.mitre_mapper.evaluate_command(command, self.interactions)

        if isinstance(mitre_result, MitreMappingError):
          logger.error(f"MITRE mapping error for command '{command}': {mitre_result.error_type} - {mitre_result.error_message}")

        latency_ms = round((time.time() - start_time) * 1000, 2)

        if self.enable_metrics:
          metrics_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "session_id": self.session_id,
            "llm_model": self.mitre_mapper.llm_model,
            "event_type": "correlation",
            "command": command,
            "command_history": [interaction.command for interaction in self.interactions],
            "mitre_mapping_error": mitre_result.error_type if isinstance(mitre_result, MitreMappingError) else None,
            "predicted_technique": mitre_result.technique_id if isinstance(mitre_result, MitreMapping) else None,
            "confidence": mitre_result.confidence if isinstance(mitre_result, MitreMapping) else 0.0,
            "latency_ms": latency_ms
          }
          with open(self.metrics_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(metrics_data) + "\n")

        if isinstance(mitre_result, MitreMapping):
          target_interaction.mitre_mapping = mitre_result
          if mitre_result.confidence >= self.engage_engine_confidence_threshold:
            engage_details = self.engage_parser.get_engage_activities_for_technique(mitre_result.technique_id)
            if len(engage_details) == 0:
              logger.warning(f"No Engage activities found for MITRE technique '{mitre_result.technique_id}' for command '{command}'.")
              return
            description = self.attack_data.get(mitre_result.technique_id, "No description available.")
            if self.vfs is None or self.virtual_shell is None:
              logger.error(f"Session environment not bound. Cannot react to command '{command}'.")
              return
            previously_used_capabilities = [
              step.capability_name
              for interaction in self.interactions
              if interaction.engage_details
              for step in interaction.engage_details.steps
            ]
            observed_attacker_behavior = self._summarize_observed_attacker_behavior()
            try:
              engage_result = self.engage_engine.evaluate_and_react(
                self.session_id, command, description, engage_details, self.vfs, self.virtual_shell,
                previously_used_capabilities,
                observed_attacker_behavior,
              )
              target_interaction.engage_details = engage_result
            except ValidationError as e:
              logger.error(f"Error validating fields for command '{command}': {e}")
      except Exception as e:
        logger.error(f"Error during background analysis for command '{command}': {e}")
    
    ai_thread: threading.Thread | None = None
    should_analyze = (
      command.strip()
      and not command.startswith("logout")
      and not command.startswith("exit")
      and command.strip() not in _PERIODIC_RECON_COMMANDS
    )
    if should_analyze:
      ai_thread = threading.Thread(
        target=background_analisis,
        args=(command, interaction),
        daemon=True
      )
      self.analysis_threads.append(ai_thread)
      ai_thread.start()

    return interaction, ai_thread

  
  def finalize_and_export(self, exit_reason: str):
    if self.analysis_threads:
      logger.info(f"Syncronizing threads: Waiting for {len(self.analysis_threads)} MITRE analyses to complete...")
      for thread in self.analysis_threads:
        if thread.is_alive():
          thread.join()
      logger.success("All background analyses have completed.")
    
    session_meta = SessionInfo(
      start_time=self.start_time,
      end_time=datetime.now(UTC),
      total_commands=len(self.interactions),
      exit_reason=exit_reason
    )

    if not self.auth_info:
      raise ValueError("Authentication information is missing. Cannot finalize session without authentication data.")
    
    if not self.env_info:
      raise ValueError("Environment information is missing. Cannot finalize session without environment data.")

    session_data = Session(
      session_id=self.session_id,
      network=self.network_info,
      environment=self.env_info,
      authentication=self.auth_info,
      interactions=self.interactions,
      session_metadata=session_meta
    )
    logger.info(f"Finalizing session: {self.session_id}")
    session_json = session_data.model_dump_json(indent=2)
    return session_json