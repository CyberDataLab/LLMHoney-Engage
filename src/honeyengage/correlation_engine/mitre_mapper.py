"""Technique Correlator: maps each command, with its recent history, to an ATT&CK technique and a confidence using a language model."""

import ast
import json
import os
import re
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

from src.common.timing import measure
from src.honeyengage.telemetry.models import InteractionInfo, MitreMapping, MitreMappingError

MAX_INTERACTION_CONTEXT = 5

MITRE_EXAMPLES = [
  (
    ["ps -aux"],
    "T1057",
    0.97,
    "The command 'ps -aux' is used to list all running processes on a system. This maps to process discovery with high confidence.",
  ),
  (
    ["kldstat | grep -i \"vmm\""],
    "T1082",
    0.93,
    "The command 'kdstat' is used to display kernel statistics. This maps to system information discovery with high confidence.",
  ),
  (
    ["whoami", "users", "id"],
    "T1033",
    0.94,
    "The command history shows current user discovery followed by user and group enumeration. The sequence strongly indicates system information discovery.",
  ),
  (
    ["cd /var/log", "ls", "cat auth.log"],
    "T1083",
    0.78,
    "The earlier navigation into /var/log makes the later ls and cat auth.log commands part of a file and directory discovery sequence influenced by prior context.",
  ),
  (
    ["sockstat", "netstat", "who -a"],
    "T1049",
    0.97,
    "The commands 'sockstat', 'netstat', and 'who -a' are used to display active network connections and user information. This maps to System Network Connections Discovery with high confidence.",
  ),
  (
    ["cat /etc/passwd"],
    "T1003",
    0.99,
    "The command 'cat' is used to read the contents of the /etc/passwd file. This maps to credential access with very high confidence.",
  ),
  (
    ["cat /sys/class/dmi/id/anyfile"],
    "T1082",
    0.92,
    "The command 'cat' is used to dump the contents of a file in the directory /sys/class, wich contains information about the system. This maps to system information discovery with very high confidence.",
  ),
  (
    ["scp maliciousfile.txt user@remotehost:/tmp"],
    "T1105",
    0.84,
    "The command 'scp' is used to securely copy a file to a remote host. This maps to ingress tool transfer with high confidence.",
  ),
  (
    ["findmnt -t nfs"],
    "T1083",
    0.77,
    "The command 'findmnt' is used to display information about mounted filesystems. This maps to file and directory discovery with moderate confidence.",
  ),
  (
    ["sudo -l", "sudo command"],
    "T1548",
    0.69,
    "The command 'sudo' is used to execute a command with elevated privileges. This maps to abuse elevation control mechanism with moderate confidence.",
  ),
  (
    ["chmod 777 /dir/examplefile"],
    "T1222",
    0.95,
    "The command 'chmod' is used to change the permissions of a file. This maps to file and directory permissions modification with high confidence.",
  ),
  (
    ["unknowncommand -arg"],
    "T1059",
    0.15,
    "The command 'unknowncommand -arg' is not recognized. The mapping is uncertain.",
  ),
  (
    ["gdsgya"],
    "T1098",
    0.06,
    "The command 'gdsgya' is probably a typo or unknown command. The mapping is uncertain.",
  ),
  (
    ["[ \"$(uname)\" = 'FreeBSD' ] && sysrc tor_enable=\"YES\" && service tor start"],
    "T1543",
    0.72,
    "The command conditionally enables and starts a system service (tor) via the BSD service-management idiom sysrc/service, gated on OS detection. This maps to Create or Modify System Process with moderate-high confidence despite the unfamiliar sysrc syntax.",
  ),
  (
    ["echo \"* * * * * /tmp/evil.sh\" > /tmp/persistevil && crontab /tmp/persistevil"],
    "T1053.003",
    0.9,
    "The command writes a cron schedule line to a file via echo/redirect and then installs it with crontab. This is a textbook Scheduled Task/Job: Cron persistence pattern regardless of the exact redirect/filename used.",
  ),
  (
    ["cat script.sh | base64 | xxd -p | sed 's/ //g'"],
    "T1027",
    0.8,
    "The command pipes a script's contents through base64 and xxd to re-encode it, a common obfuscation/encoding pattern for staging or transferring a payload in an altered form. This maps to Obfuscated Files or Information with high confidence even without recognizing every tool in the pipeline.",
  ),
]

logger.add("logs/honeyengage_mitre_mapper.log", rotation="10 MB")

load_dotenv()

class MitreMapper:
  def __init__(self, llm_client, llm_model, attack_data_keys: list[str]):
    self.llm_client = llm_client
    self.llm_model = llm_model
    self.temperature = float(os.getenv("HONEYENGAGE_CORRELATION_ENGINE_TEMPERATURE", 0.1))
    self.max_tokens = int(os.getenv("HONEYENGAGE_CORRELATION_MAX_TOKENS", 400))
    self.attack_data_keys = attack_data_keys
    self.deprecated_alias = self._load_deprecated_alias()

  @staticmethod
  def _load_deprecated_alias() -> dict[str, str]:
    alias_path = Path(__file__).with_name("attack_deprecated_alias.json")
    if not alias_path.exists():
      logger.warning(f"Deprecated-alias table not found at {alias_path}; revoked IDs will not be normalized.")
      return {}
    try:
      with alias_path.open("r", encoding="utf-8") as f:
        return json.load(f)
    except Exception as exc:
      logger.error(f"Failed to load deprecated-alias table: {exc}")
      return {}

  def _format_interactions(self, interactions: list[InteractionInfo]) -> str:
    recent_interactions = interactions[-MAX_INTERACTION_CONTEXT:]
    return "\n".join(
      f"[{index + 1}] {interaction.command}"
      for index, interaction in enumerate(recent_interactions)
    )

  def _build_example_text(self, limit: int | None = None) -> str:
    example_blocks: list[str] = []
    examples_to_use = MITRE_EXAMPLES if limit is None else MITRE_EXAMPLES[:limit]
    for commands, technique_id, confidence, cti_sentence in examples_to_use:
      target_cmd = commands[-1]
      history_cmds = commands[:-1]

      if history_cmds:
        history_lines = "\n".join(f"[{index + 1}] {cmd}" for index, cmd in enumerate(history_cmds))
      else:
        history_lines = "No prior history."
      
      example_blocks.append(
        f"Interaction History (Context):\n{history_lines}\n"
        f"Target Command to Evaluate: '{target_cmd}'\n"
        "Expected mapping:\n"
        f'{{"technique_id": "{technique_id}", "confidence": {confidence}, "cti_sentence": "{cti_sentence}"}}'
      )

    return "\n\n".join(example_blocks)

  def _build_mapping_prompt(self, current_command: str, interactions: list[InteractionInfo]) -> tuple[str, str]:
    history_text = self._format_interactions(interactions)

    is_tiny_model = "tinyllama" in self.llm_model.lower()

    if is_tiny_model:
      system_prompt = "You are a Linux command classifier. Output ONLY valid JSON."
      user_prompt = (
        f"History: {history_text if history_text else 'None'}\n"
        f"Target Command: '{current_command}'\n\n"
        "Classify the Target Command. Respond ONLY with a JSON object containing:\n"
        "- technique_id (string, e.g., 'T1082')\n"
        "- confidence (float between 0.0 and 1.0)\n"
        "- cti_sentence (string, brief explanation)\n\n"
        "JSON:"
      )

    else:
      example_text = self._build_example_text()

      system_prompt = (
        "You are an expert Cyber Threat Intelligence analyst mapping Linux shell commands to MITRE ATT&CK techniques. "
        "Return only valid JSON and do not wrap it in markdown. "
        "Your core task is to evaluate the 'Target Command' ONLY, using the 'Interaction History' solely as context to resolve ambiguities. "
        "Always return a CURRENT MITRE ATT&CK technique ID from the latest matrix; never return revoked or deprecated IDs "
        "(for example, use T1059.001 rather than the retired T1086, or T1021.001 rather than the retired T1076)."
      )
      user_prompt = (
        f"Examples:\n{example_text}\n\n"
        f"Interaction History (Context):\n{history_text if history_text else 'No prior history.'}\n\n"
        f"Target Command to Evaluate: '{current_command}'\n\n"
        "Task: Identify the most likely MITRE ATT&CK technique for the 'Target Command' above. "
        "Return a single JSON object with these exact fields:\n"
        '{"technique_id": "T####", "confidence": 0.0, "cti_sentence": "<sentence detailing the reasoning for THIS specific target command>"}'
      )

    return system_prompt, user_prompt

  def _parse_prediction_payload(self, raw_output: str) -> object:
    text = raw_output.strip()
    if text.startswith("```"):
      text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
      text = re.sub(r"\s*```$", "", text)

    try:
      return json.loads(text)
    except json.JSONDecodeError:
      match = re.search(r"\{.*\}", text, re.DOTALL)
      if match:
        candidate = match.group(0)
        try:
          return json.loads(candidate)
        except json.JSONDecodeError:
          try:
            return ast.literal_eval(candidate)
          except (ValueError, SyntaxError):
            return None

      try:
        return ast.literal_eval(text)
      except (ValueError, SyntaxError):
        return None

  def _coerce_payload(self, payload: object) -> dict | None:
    if isinstance(payload, dict):
      if "mappings" in payload and isinstance(payload["mappings"], list):
        for item in reversed(payload["mappings"]):
          if isinstance(item, dict):
            return item
      return payload

    if isinstance(payload, list):
      for item in reversed(payload):
        if isinstance(item, dict):
          return item

    return None

  def _build_prediction(self, payload: dict, interactions: list[InteractionInfo]) -> MitreMapping | MitreMappingError | None:
    if not payload:
      return None

    technique_id = str(payload.get("technique_id", "")).strip()
    cti_sentence = str(payload.get("cti_sentence", "")).strip()

    try:
      confidence = float(payload.get("confidence", 0.0))
    except (TypeError, ValueError):
      confidence = 0.0

    if not technique_id or not cti_sentence:
      return None

    normalized_id = self.deprecated_alias.get(technique_id)
    if normalized_id and normalized_id in self.attack_data_keys:
      logger.debug(f"Normalized revoked technique {technique_id} -> {normalized_id}")
      technique_id = normalized_id

    if technique_id not in self.attack_data_keys:
      return MitreMappingError(
        error_type="TechniqueNotFound",
        error_message=f"MITRE technique '{technique_id}' not found in local ATT&CK data."
      )

    confidence = max(0.0, min(1.0, confidence))

    return MitreMapping(
      technique_id=technique_id,
      confidence=round(confidence, 3),
      cti_sentence=cti_sentence,
    )

  def evaluate_command(self, command: str, interactions: list[InteractionInfo]) -> MitreMapping | MitreMappingError:
    if not command.strip():
      return MitreMappingError(
        error_type="EmptyCommand",
        error_message="The provided command is empty or whitespace.",
      )

    if not self.llm_client or not self.llm_model:
      logger.error("LLM client or model not configured. Cannot evaluate the command.")
      return MitreMappingError(
        error_type="LLMNotConfigured",
        error_message="LLM client or model not configured. Cannot evaluate the command.",
      )

    try:
      system_prompt, user_prompt = self._build_mapping_prompt(command, interactions)

      with measure("technique_correlator"):
        response = self.llm_client.chat.completions.create(
          model=self.llm_model,
          messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
          ],
          temperature=self.temperature,
          max_tokens=self.max_tokens,
          response_format={"type": "json_object"},
        )

      raw_output = response.choices[0].message.content if response.choices else None
      if not raw_output:
        logger.error("Unexpected response from OpenAI: No content received in the response.")
        return MitreMappingError(
          error_type="LLMResponseError",
          error_message="Unexpected response from OpenAI: No content received in the response.",
        )

      payload = self._parse_prediction_payload(raw_output)
      payload = self._coerce_payload(payload)
      if not isinstance(payload, dict):
        return MitreMappingError(
          error_type="InvalidPayload",
          error_message=f"Invalid MITRE mapping payload returned by the LLM: {raw_output}",
        )

      mitre_mapping = self._build_prediction(payload, interactions)
      if isinstance(mitre_mapping, MitreMappingError):
        return mitre_mapping
      if not mitre_mapping:
        logger.warning(f"LLM returned an unusable MITRE mapping for command '{command}': {raw_output}")
        return MitreMappingError(
          error_type="UnusableMapping",
          error_message=f"LLM returned an unusable MITRE mapping for command '{command}': {raw_output}",
        )

      logger.info(f"Generated MITRE mapping for command '{command}': {mitre_mapping.model_dump()}")
      return mitre_mapping

    except Exception as e:
      logger.error(f"Error in live MITRE prediction: {e}")
      return MitreMappingError(
        error_type="UnexpectedError",
        error_message=f"An unexpected error occurred while evaluating the command: {e}",
      )