"""MITRE Engage Planner and Artifact Factory. Maps an identified technique to Engage activities, chooses a scenario template (or, in the control conditions, a set of capabilities), generates the artifact contents with a language model around a shared subject, and deploys them on the emulated host."""

import ast
import hashlib
import importlib
import inspect
import json
import os
import pkgutil
import random
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from src.common.timing import measure
from loguru import logger

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.engage_engine.engage_mapping import EngageDetails, EngageResult, EngageStepResult
from src.honeyengage.engage_engine.engage_parser import EngageParser
from src.honeyengage.engage_engine.scenario_catalog import ScenarioTemplate, scenarios_for_activity
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import ProcessData, VirtualShell

MIN_CHAIN_LENGTH = 2
MAX_CHAIN_LENGTH = 4
CHAIN_GENERATION_ATTEMPTS = 3

logger.add("logs/honeyengage_engage_engine.log", rotation="10 MB")

class LlmSyntaxError(Exception):
  pass

class EngageEngine:

  _VARIETY_MIN_REDEPLOYS = 3

  def __init__(
      self,
      llm_client,
      capabilities_mapping_url: str = "/src/honeyengage/engage_engine/activity_capabilities_mapping.json",):
    self.llm_client = llm_client
    self.llm_model = os.getenv("HONEYENGAGE_ENGAGE_MODEL", "llama3.1")
    self.temperature = float(os.getenv("HONEYENGAGE_ENGAGE_ENGINE_TEMPERATURE", 0.3))
    self.coa_mode = os.getenv("HONEYENGAGE_COA_MODE", "chain").lower()
    self.engage_parser = EngageParser()
    self.capabilities_registry = self.discover_capabilities("src.honeyengage.engage_engine.capabilities")
    self.activity_capabilities_mapping = self.load_activity_capabilities_mapping(capabilities_mapping_url)
    self.enable_metrics = os.getenv("ENABLE_METRICS", "false").lower() == "true"
    if self.enable_metrics:
      self.metrics_file = os.getenv("METRICS_FILE", "defend_metrics.jsonl")
    self._used_scenario_ids: set[str] = set()
    self._same_ttp_activity: dict[str, str] = {}
    self._generated_option_values: dict[tuple[str, str], list[str]] = {}
    self._generated_option_values_lock = threading.Lock()
    self._active_narrative: str | None = None

  def discover_capabilities(self, package_name: str) -> dict[str, type[Capability]]:
    capabilities: dict[str, type[Capability]] = {}

    try:
      package = importlib.import_module(package_name)
    except ImportError as e:
      logger.error(f"Failed to import package '{package_name}': {e}")
      return capabilities
    
    for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
      if is_pkg:
        continue

      try:
        module = importlib.import_module(module_name)

        for name, obj in inspect.getmembers(module, inspect.isclass):
          if (
            obj.__module__ == module_name
            and name.endswith("Capability")
            and name != "Capability"
            and issubclass(obj, Capability)
          ):
            capabilities[name] = obj
      except ImportError as e:
        logger.error(f"Failed to import module '{module_name}': {e}")
    return capabilities
      
  
  def load_activity_capabilities_mapping(self, capabilities_mapping_url: str) -> dict[str, list[str]]:
    url = Path(capabilities_mapping_url)

    if not url.exists():
      repo_root = Path(__file__).resolve().parents[3]
      candidate = repo_root / capabilities_mapping_url.lstrip("/")
      if candidate.exists():
        url = candidate
      else:
        logger.warning(f"Capabilities mapping file not found at {capabilities_mapping_url}")
        return {}

    with url.open("r", encoding="utf-8") as cache_file:
      raw = json.load(cache_file)

    mapping: dict[str, list[str]] = {}
    for eac_id, value in raw.items():
      capabilities: list[str] = []
      for capability in value.get("capabilities", []):
        name = capability.get("name")
        if name:
          capabilities.append(name)

      mapping[str(eac_id)] = capabilities

    return mapping

  def _session_rng(self, session_id: str) -> random.Random:
    base_seed = os.getenv("HONEYENGAGE_SEED")
    if base_seed is None:
      return random.Random()
    digest = hashlib.sha256(f"{base_seed}:{session_id}".encode()).hexdigest()
    return random.Random(int(digest, 16))

  def evaluate_and_react(
    self,
    session_id: str,
    command: str,
    description: str,
    engage_details: list[EngageDetails],
    vfs: VirtualFileSystem,
    virtual_shell: VirtualShell,
    previously_used_capabilities: list[str] | None = None,
    observed_attacker_behavior: str | None = None,
  ) -> EngageResult:
    valid_capabilities: list[tuple[str, str]] = []
    activity_ids: list[str] = []

    for detail in engage_details:
      activity = detail.activity.activity_id
      activity_ids.append(activity)
      capabilities = self.activity_capabilities_mapping.get(activity, [])
      valid_capabilities.extend([(activity, cap) for cap in capabilities])

    if self.coa_mode == "static":
      return EngageResult(result_status="static_no_reaction", eac_id="", capability_name="", error_message="")

    if not valid_capabilities:
      return EngageResult(result_status="unsupported_capability", eac_id="", capability_name="", error_message="No valid capabilities for the detected activities")

    session_rng = self._session_rng(session_id)

    if self.coa_mode == "single":
      chain = [valid_capabilities[session_rng.randrange(len(valid_capabilities))]]
    elif self.coa_mode == "same_ttp":
      activity = self._same_ttp_activity.get(session_id)
      if activity is None:
        activity = activity_ids[session_rng.randrange(len(activity_ids))]
        self._same_ttp_activity[session_id] = activity
      caps_for_activity = [(activity, cap) for cap in self.activity_capabilities_mapping.get(activity, [])]
      if not caps_for_activity:
        caps_for_activity = valid_capabilities
      session_rng.shuffle(caps_for_activity)
      chain = caps_for_activity[:MAX_CHAIN_LENGTH]
    elif self.coa_mode == "multi_ttp":
      shuffled = list(valid_capabilities)
      session_rng.shuffle(shuffled)
      chain = shuffled[:MAX_CHAIN_LENGTH]
    else:
      candidate_scenarios: list[ScenarioTemplate] = []
      for activity in activity_ids:
        candidate_scenarios.extend(scenarios_for_activity(activity, role_id=virtual_shell.persona.role_id))

      if candidate_scenarios:
        chain = self._plan_engagement_chain_from_scenarios(
          command, description, candidate_scenarios, valid_capabilities,
          previously_used_capabilities or [], virtual_shell, session_rng,
          observed_attacker_behavior,
        )
      else:
        chain = [valid_capabilities[session_rng.randrange(len(valid_capabilities))]]

    coherent_options = None
    if self.coa_mode == "chain" and len(chain) > 1 and self.llm_client and self.llm_model:
      for _ in range(CHAIN_GENERATION_ATTEMPTS):
        coherent_options = self._build_coherent_chain_options(chain, command, description, session_id)
        if coherent_options is not None:
          break
      if coherent_options is None:
        logger.warning(
          f"Coherent chain generation failed {CHAIN_GENERATION_ATTEMPTS} times for '{command}'; "
          "deploying nothing rather than an incoherent chain."
        )
        return EngageResult(
          result_status="failure",
          eac_id=chain[0][0],
          capability_name=chain[-1][1],
          error_message="coherent chain generation failed; no artifacts deployed",
          steps=[],
        )

    if coherent_options is not None:
      precomputed_options_list = coherent_options
    else:
      with ThreadPoolExecutor(max_workers=max(1, len(chain))) as executor:
        def fetch_options(eac_id_and_capability: tuple[str, str]) -> object | Exception:
          _, capability_name = eac_id_and_capability
          capability_class = self.capabilities_registry.get(capability_name)
          if capability_class is None:
            return None
          try:
            return self._build_capability_options(capability_name, capability_class, command, description, session_id)
          except Exception as exc:
            return exc

        precomputed_options_list = list(executor.map(fetch_options, chain))

    steps: list[EngageStepResult] = []
    for (eac_id, capability_name), precomputed_options in zip(chain, precomputed_options_list):
      steps.append(self.execute_deception(
        session_id, eac_id, capability_name, command, description, vfs, virtual_shell,
        precomputed_options=precomputed_options,
      ))

    first_failure = next((step for step in steps if step.result_status != "success"), None)
    summary = first_failure if first_failure else steps[-1]

    return EngageResult(
      result_status=summary.result_status,
      eac_id=summary.eac_id,
      capability_name=summary.capability_name,
      error_message=summary.error_message,
      steps=steps,
    )

  def _plan_engagement_chain_from_scenarios(
    self,
    command: str,
    description: str,
    candidate_scenarios: list[ScenarioTemplate],
    valid_capabilities: list[tuple[str, str]],
    previously_used_capabilities: list[str],
    virtual_shell: VirtualShell,
    session_rng: random.Random,
    observed_attacker_behavior: str | None = None,
  ) -> list[tuple[str, str]]:
    unused_scenarios = [s for s in candidate_scenarios if s.scenario_id not in self._used_scenario_ids]
    if unused_scenarios:
      candidate_scenarios = unused_scenarios

    fallback_scenario = candidate_scenarios[session_rng.randrange(len(candidate_scenarios))]
    activity_by_capability: dict[str, str] = {}
    for activity, capability_name in valid_capabilities:
      activity_by_capability.setdefault(capability_name, activity)

    def resolve_chain(scenario: ScenarioTemplate) -> list[tuple[str, str]]:
      self._used_scenario_ids.add(scenario.scenario_id)
      self._active_narrative = scenario.narrative
      resolved = [(activity_by_capability.get(name, scenario.eac_id), name) for name in scenario.capability_chain]

      if len(resolved) < MAX_CHAIN_LENGTH:
        already = {name for _, name in resolved}
        extras = [
          pair for pair in valid_capabilities
          if pair[1] not in already and pair[1] in self.capabilities_registry
        ]
        session_rng.shuffle(extras)
        resolved.extend(extras[:MAX_CHAIN_LENGTH - len(resolved)])
      return resolved

    if not self.llm_client or not self.llm_model or len(candidate_scenarios) == 1:
      return resolve_chain(fallback_scenario)

    scenario_list_text = "\n".join(
      f"- {s.scenario_id}: {s.narrative} (runs: {', '.join(s.capability_chain)})" for s in candidate_scenarios
    )
    history_text = ", ".join(previously_used_capabilities[-10:]) if previously_used_capabilities else "None"

    system_prompt = (
      "You are the deception planning module of an adaptive SSH honeypot. An attacker just executed a "
      "command that was mapped to a MITRE ATT&CK technique with high confidence. Your job is to pick ONE "
      "curated scenario (a pre-defined 'Course of Action') to deploy in response.\n"
      "Your overriding goal is to keep the attacker engaged and exploring for as long as possible.\n"
      "ABSOLUTE RULE: every scenario you deploy must show the attacker something it has NOT already "
      "seen this session. Never re-run a scenario already listed as used, and never pick one whose "
      "artifacts would land in the same places a previous one already touched -- an attacker that keeps "
      "finding the same file, process or account it found ten minutes ago concludes the box is inert and "
      "leaves. Prefer whichever remaining scenario best continues or deepens the cover story already "
      "built this session rather than contradicting it.\n"
      "You are also given a short profile of how THIS attacker has behaved so far this session (pace, "
      "how broadly they are probing, whether prior deceptions landed). Use it to react to the ADVERSARY, "
      "not just the single command: a fast, broadly-probing attacker warrants a scenario that plants a "
      "richer trail to chase, while a slow, narrowly-focused one warrants deepening the specific thread "
      "they are already pulling on. This behavioral summary is inferred only from observable session "
      "activity; treat it as a hint, never as ground truth about who the attacker really is.\n"
      "You MUST respond EXCLUSIVELY with a JSON object: "
      '{"scenario_id": "the_chosen_id", "reasoning": "short justification"}. '
      "The scenario_id MUST be copied verbatim from the provided list."
    )
    behavior_text = observed_attacker_behavior or "No behavioral profile available yet."
    user_prompt = (
      f"Command executed by the attacker: {command}\n"
      f"Technique context: {description}\n"
      f"This machine's persona: {virtual_shell.persona.display_name}\n"
      f"Observed attacker behavior this session: {behavior_text}\n"
      f"Capabilities already used this session: {history_text}\n\n"
      f"Candidate scenarios for this technique and persona:\n{scenario_list_text}\n\n"
      "Return the JSON choice now."
    )

    try:
      with measure("engage_planner"):
        response = self.llm_client.chat.completions.create(
          model=self.llm_model,
          messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
          ],
          temperature=self.temperature,
          max_tokens=200,
          response_format={"type": "json_object"},
        )
      raw_output = response.choices[0].message.content if response.choices else None
      if not raw_output:
        return resolve_chain(fallback_scenario)
      payload = self._parse_options_payload(raw_output)
    except Exception as exc:
      logger.warning(f"Scenario planning failed, falling back to a random candidate scenario: {exc}")
      return resolve_chain(fallback_scenario)

    if not isinstance(payload, dict):
      return resolve_chain(fallback_scenario)

    chosen_id = payload.get("scenario_id")
    chosen_scenario = next((s for s in candidate_scenarios if s.scenario_id == chosen_id), None)
    if chosen_scenario is None:
      logger.warning(f"Scenario plan referenced unknown scenario_id '{chosen_id}', falling back to a random candidate.")
      return resolve_chain(fallback_scenario)

    return resolve_chain(chosen_scenario)

  def execute_deception(
    self,
    session_id: str,
    eac_id: str,
    capability_name: str,
    command: str,
    description: str,
    vfs: VirtualFileSystem,
    virtual_shell: VirtualShell,
    precomputed_options: object | Exception | None = None,
  ) -> EngageStepResult:
    capability_class = self.capabilities_registry.get(capability_name)
    if capability_class is None:
      logger.warning(f"Unsupported deception capability '{capability_name}'.")
      return EngageStepResult(result_status="unsupported_capability", eac_id=eac_id, capability_name=capability_name, error_message="Unsupported deception capability")

    llm_error_type = None
    result: CapabilityResult | None = None
    capability_options: object = SimpleNamespace()

    try:
      if isinstance(precomputed_options, Exception):
        raise precomputed_options
      capability_options = precomputed_options if precomputed_options is not None else self._build_capability_options(
        capability_name,
        capability_class,
        command,
        description,
        session_id,
      )

      capability = capability_class(vfs, virtual_shell, eac_id, capability_options)
      result = capability.execute()

      if result is None:
        llm_error_type = "unknown_error"
      elif result.success:
        logger.success(
          f"Executed capability '{capability_name}' ({result.eac_id}): {result.message}"
        )
      else:
        llm_error_type = "llm_execution_error"
        logger.warning(
          f"Capability '{capability_name}' failed ({result.eac_id}): {result.message}"
        )
    except LlmSyntaxError:
      llm_error_type = "llm_syntax_error"
    except Exception as e:
      llm_error_type = "llm_execution_error"
      logger.error(f"Unexpected error occurred: {e}")

    result_status = llm_error_type if llm_error_type else "success" if result and result.success else "Unknown Error"
    if result:
      error_message = "" if result.success else result.message
    else:
      error_message = "LLM returned invalid options for capability" if llm_error_type == "llm_syntax_error" else "Failed to execute capability" if llm_error_type == "unknown_error" else "Unknown Error"

    if self.enable_metrics:
      planted_values: list[str] = []
      try:
        for field, value in vars(capability_options).items():
          if isinstance(value, str):
            planted_values.append(value)
          elif isinstance(value, dict):
            planted_values.extend(str(v) for v in value.values() if isinstance(v, (str, int)))
          elif isinstance(value, (list, tuple)):
            planted_values.extend(str(v) for v in value if isinstance(v, (str, int)))
      except Exception:  # pragma: no cover - options may be a bare namespace
        pass

      metrics_data = {
        "timestamp": datetime.now(UTC).isoformat(),
        "session_id": session_id,
        "llm_model": self.llm_model,
        "event_type": "deception",
        "command": command,
        "capability_name": capability_name,
        "description": description,
        "result":  result_status,
        "eac_id": result.eac_id if result else "",
        "message": result.message if result else "",
        "planted_values": planted_values,
      }
      with open(self.metrics_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics_data) + "\n")

    return EngageStepResult(
      result_status=result_status,
      eac_id=result.eac_id if result else eac_id,
      capability_name=capability_name,
      error_message=error_message
    )

  _NARRATIVE_SUBJECTS = (
    "backup-runner", "log-shipper", "cache-warmer", "report-builder",
    "index-rebuild", "cert-renew", "queue-drain", "metrics-agent",
    "session-reaper", "batch-import", "audit-collect", "media-encode",
  )

  def _stamp_narrative_subject(self, component: dict, subject: str) -> dict:
    stamped = dict(component)
    for field, value in component.items():
      if not isinstance(value, str) or not value or subject in value:
        continue
      lowered = field.lower()
      is_pathish = value.startswith("/") or "path" in lowered or "file" in lowered
      is_nameish = any(k in lowered for k in ("name", "service", "process", "unit", "user", "account", "command"))
      if not (is_pathish or is_nameish):
        continue

      if value.startswith("/"):
        head, _, tail = value.rpartition("/")
        _name, dot, ext = tail.partition(".")
        stamped[field] = f"{head}/{subject}{dot}{ext}"
      elif is_pathish:
        stamped[field] = subject
      else:
        stamped[field] = subject
    return stamped

  def _narrative_subject(self, session_id: str, narrative: str) -> str:
    digest = hashlib.sha256(f"{session_id}:{narrative}".encode()).hexdigest()
    return self._NARRATIVE_SUBJECTS[int(digest, 16) % len(self._NARRATIVE_SUBJECTS)]

  def _build_coherent_chain_options(
      self,
      chain: list[tuple[str, str]],
      command: str,
      description: str,
      session_id: str | None = None,
    ) -> list[object | Exception] | None:
    if not self.llm_client or not self.llm_model:
      return None

    specs: list[tuple[str, type[Capability], dict[str, str]]] = []
    for _, capability_name in chain:
      capability_class = self.capabilities_registry.get(capability_name)
      if capability_class is not None:
        specs.append((capability_name, capability_class, capability_class.option_fields()))
    if not specs:
      return None

    fields_text = "\n".join(
      f'"{name}": {{\n' + "\n".join(f"    {field}: {desc}" for field, desc in fields.items()) + "\n  }"
      for name, _, fields in specs
    )
    narrative = getattr(self, "_active_narrative", None) or description

    system_prompt = (
      "You are an expert system administrator AI generating configuration data "
      "for a highly realistic Ubuntu 22.04 production server. Your output MUST be "
      "strictly valid JSON. DO NOT wrap the output in Markdown blocks.\n"
      "CRITICAL RULES:\n"
      "1. NEVER use words like 'honeypot', 'fake', 'decoy', 'trap', 'test', or 'malware'.\n"
      "2. Data must look indistinguishable from a legitimate corporate server environment.\n"
      "3. ONLY output the exact fields requested for each component. No extra fields.\n"
      "4. Return ONE JSON object whose keys are EXACTLY the component names given.\n"
      "5. When a field is described as \"Dictionary\", output EXACTLY ONE JSON object for it."
    )
    subject = self._narrative_subject(session_id, narrative)

    user_prompt = (
      f"Command executed: {command}\n"
      f"Context: '{description}'\n"
      f"THE STORY THESE ARTIFACTS MUST TELL TOGETHER: {narrative}\n\n"
      f"THE SUBJECT OF THIS STORY IS: {subject}\n"
      f"Generate configuration data for these components, in order:\n{{\n{fields_text}\n}}\n\n"
      "ABSOLUTE RULE -- EVERY COMPONENT MUST NAME THE SUBJECT LITERALLY.\n"
      f"The exact string '{subject}' MUST appear inside at least one field of EVERY "
      "component: in the log line's text, in the process's command line, in the file path, "
      "in the service or account name. Build each value around it (for example "
      f"'/var/log/{subject}.log', '/usr/sbin/{subject}', 'user {subject} started ...'). "
      "They are evidence of ONE event on this host, not unrelated items, so an investigator "
      "pulling on any one thread must find it leads to the others. Beyond that, keep every "
      "value mundane and plausible for a busy production server.\n"
      "Return ONLY a raw JSON object keyed by component name."
    )

    try:
      with measure("artifact_generation_chain"):
        response = self.llm_client.chat.completions.create(
          model=self.llm_model,
          messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
          ],
          temperature=self.temperature,
          max_tokens=900 * max(1, len(specs)),
          response_format={"type": "json_object"},
        )
    except Exception as exc:
      logger.error(f"Coherent chain generation failed, falling back to independent options: {exc}")
      return None

    raw_output = response.choices[0].message.content if response.choices else None
    if not raw_output:
      return None
    payload = self._parse_options_payload(raw_output)
    if not isinstance(payload, dict):
      logger.warning(f"Coherent chain generation returned a non-object payload: {raw_output!r}")
      return None

    generated: dict[str, object] = {}
    for capability_name, _, option_fields in specs:
      component = payload.get(capability_name)
      if not isinstance(component, dict):
        logger.warning(f"Coherent chain payload missing/invalid component '{capability_name}'; falling back.")
        return None
      component = self._coerce_capability_payload(capability_name, component, option_fields)
      component = self._stamp_narrative_subject(component, subject)
      generated[capability_name] = SimpleNamespace(**component)

    results: list[object | Exception] = [generated.get(capability_name) for _, capability_name in chain]

    logger.info(f"Generated {len(results)} cross-referencing artifacts for narrative: {narrative}")
    return results

  def _build_capability_options(
      self,
      capability_name: str,
      capability_class: type[Capability],
      command: str,
      description: str,
      session_id: str | None = None,
    ) -> object:
    option_fields = capability_class.option_fields()
    if not option_fields:
      return SimpleNamespace()

    if not self.llm_client or not self.llm_model:
      logger.warning(
        f"LLM client or model not configured. Cannot generate options for capability '{capability_name}'."
      )
      return SimpleNamespace()

    field_description_text = "\n".join(
      f"- {field}: {description}" for field, description in option_fields.items()
    )

    system_prompt = (
      "You are an expert system administrator AI generating configuration data "
      "for a highly realistic Ubuntu 22.04 production server. Your output MUST be "
      "strictly valid JSON. DO NOT wrap the output in Markdown blocks.\n"
      "CRITICAL RULES:\n"
      "1. NEVER use words like 'honeypot', 'fake', 'decoy', 'trap', 'test', or 'malware'.\n"
      "2. Data must look indistinguishable from a legitimate corporate server environment.\n"
      "3. ONLY output the exact fields requested. DO NOT hallucinate or add extra fields.\n"
      "4. DO NOT wrap the fields inside objects like command, arguments, options, payload, or data.\n"
      "5. When a field is described as \"Dictionary\", output EXACTLY ONE JSON object for it -- never a JSON "
      "array/list of multiple objects, even if several would also be plausible."
    )
    previous_values = list(self._generated_option_values.get((session_id or "", capability_name), []))
    if len(previous_values) >= self._VARIETY_MIN_REDEPLOYS:
      variety_text = (
        "\nALREADY PRESENT ON THIS HOST (created earlier in this same session):\n"
        + "\n".join(f"- {value}" for value in previous_values[-8:])
        + "\nABSOLUTE RULE: the values you return MUST be clearly different from every one listed above "
        "-- different names, different addresses/paths, different identifiers. A real server accumulates "
        "DISTINCT artifacts over time; returning something equivalent to what is already there makes the "
        "host look inert and static, which is exactly what must be avoided. Stay equally mundane and "
        "plausible, just genuinely different.\n"
      )
    else:
      variety_text = ""

    user_prompt = (
      f"Command executed: {command}\n"
      f"Context: '{description}'\n"
      f"Task: Generate configuration data for the system component: '{capability_name}'.\n"
      f"Required Fields and their descriptions:\n{field_description_text}\n"
      f"{variety_text}\n"
      "INSTRUCTIONS:\n"
      "Fill all required fields with highly convincing, mundane values typical of a busy Linux server. "
      "Draw on the full range of software a real server runs -- web servers, databases, caches, message "
      "queues, monitoring agents, backup jobs, container runtimes, internal tooling -- rather than "
      "defaulting to the same one or two every time. "
      "Return ONLY a raw JSON object."
    )

    try:
      with measure("artifact_generation_single"):
        response = self.llm_client.chat.completions.create(
          model=self.llm_model,
          messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
          ],
          temperature=self.temperature,
          max_tokens=900,
          response_format={"type": "json_object"},
        )
    except Exception as exc:
      logger.error(f"Error requesting options from LLM for '{capability_name}': {exc}")
      raise LlmSyntaxError(f"Error requesting options from LLM for '{capability_name}': {exc}") from exc

    raw_output = response.choices[0].message.content if response.choices else None
    if not raw_output:
      logger.warning(f"LLM returned no content for capability '{capability_name}'.")
      raise LlmSyntaxError(f"No content returned for capability '{capability_name}'.")

    payload = self._parse_options_payload(raw_output)
    if not isinstance(payload, dict):
      logger.warning(f"LLM returned invalid options for capability '{capability_name}': {raw_output}")
      raise LlmSyntaxError(f"Invalid options payload for capability '{capability_name}': {raw_output}")

    payload = self._coerce_capability_payload(capability_name, payload, option_fields)
    if session_id is not None:
      summary = ", ".join(f"{field}={payload[field]!r}" for field in option_fields if field in payload)
      if summary:
        with self._generated_option_values_lock:
          self._generated_option_values.setdefault((session_id, capability_name), []).append(summary)
    result = SimpleNamespace(**payload)
    return result

  def _parse_options_payload(self, raw_output: str) -> object:
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

  def _coerce_capability_payload(self, capability_name: str, payload: dict, option_fields: dict[str, str]) -> dict:
    payload = self._unwrap_capability_payload(payload, set(option_fields.keys()))

    if len(payload) == 1 and capability_name in payload and isinstance(payload[capability_name], dict):
        payload = payload[capability_name]
    if capability_name in {"inject_fake_process", "inject_fake_process_capability"}:
      process_data = payload.get("process_data")
      if isinstance(process_data, dict):
        payload["process_data"] = ProcessData(**process_data)

    if capability_name in {"inject_fake_network_connection", "inject_fake_network_connection_capability"}:
      network_data = payload.get("network_data")
      if isinstance(network_data, dict):
        payload["network_data"] = network_data

    return payload

  def _unwrap_capability_payload(self, payload: object, required_fields: set[str]) -> dict:
    if not isinstance(payload, dict):
      return {}

    if required_fields and required_fields.issubset(payload.keys()):
      return payload

    wrapper_keys = ("arguments", "args", "options", "payload", "data", "fields", "command")
    for key in wrapper_keys:
      nested = payload.get(key)
      if isinstance(nested, dict):
        candidate = self._unwrap_capability_payload(nested, required_fields)
        if required_fields.issubset(candidate.keys()):
          return candidate

    for value in payload.values():
      if isinstance(value, dict):
        candidate = self._unwrap_capability_payload(value, required_fields)
        if required_fields.issubset(candidate.keys()):
          return candidate

    return payload