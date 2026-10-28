"""Attack Planner: chooses the next ATT&CK technique and the follow-up commands with a language model."""

import json
import os
import re
from dataclasses import dataclass

from loguru import logger

from src.common.timing import measure
from src.llmattacker.threat_actor.profile import ThreatActorProfile

logger.add("logs/attack_planner.log", rotation="10 MB")


@dataclass
class TechniqueOutcome:
  technique_id: str
  commands_executed: int
  honeypot_detected: bool
  avg_credibility: float
  new_notable_tokens: int = 0
  new_artifact_classes: frozenset[str] = frozenset()
  corroborated_tokens: int = 0


@dataclass
class NextStepDecision:
  next_technique_id: str | None
  reasoning: str = ""
  request_bonus_technique: bool = False


class AttackPlanner:

  def __init__(self, llm_client, profile: ThreatActorProfile):
    self.llm_client = llm_client
    self.llm_model = os.getenv("LLMATTACKER_LLM_MODEL", "llama3.1")
    self.temperature = float(os.getenv("LLMATTACKER_TEMPERATURE", 0.2))
    self.profile = profile

  def _fallback_next_step(self, remaining_techniques: list[str]) -> NextStepDecision:
    if not remaining_techniques:
      return NextStepDecision(next_technique_id=None, reasoning="No techniques remain (fallback).")
    return NextStepDecision(next_technique_id=remaining_techniques[0], reasoning="Deterministic fallback: next in fixed order.")

  def decide_next_step(
    self,
    remaining_techniques: list[str],
    history: list[TechniqueOutcome],
    bonus_available: bool = False,
  ) -> NextStepDecision:
    if not remaining_techniques and not bonus_available:
      return NextStepDecision(next_technique_id=None, reasoning="No techniques remain.")

    if not self.llm_client or not self.llm_model:
      return self._fallback_next_step(remaining_techniques)

    history_text = "\n".join(
      f"- {h.technique_id}: {h.commands_executed} command(s), "
      f"avg_credibility={h.avg_credibility:.2f}, "
      f"{'HONEYPOT SUSPECTED' if h.honeypot_detected else 'looked legitimate'}"
      for h in history
    ) or "None yet (this is the first technique)."

    if history:
      session_avg_credibility = sum(h.avg_credibility for h in history) / len(history)
      suspicious_count = sum(1 for h in history if h.honeypot_detected)
      total_commands_so_far = sum(h.commands_executed for h in history)
      session_summary = (
        f"Techniques attempted: {len(history)} | Commands run: {total_commands_so_far} | "
        f"Session-wide avg_credibility: {session_avg_credibility:.2f} | "
        f"Techniques that looked suspicious: {suspicious_count}/{len(history)}"
      )
    else:
      session_summary = "Nothing attempted yet."

    remaining_text = "\n".join(f"- {t}" for t in remaining_techniques) or "None -- your assigned list is exhausted."

    bonus_instructions = (
      "\nYour assigned technique list may run out before you're done. If it does, and everything you've seen "
      "so far has looked convincing and consistent (high avg_credibility, no HONEYPOT SUSPECTED entries), a "
      "Persistent or Targeted actor with real appetite for this target would look for ONE more avenue instead "
      "of stopping. Set \"request_bonus_technique\": true (with next_technique_id set to null, since you don't "
      "know the bonus technique's id yet) to ask for that. Only do this if the session has genuinely earned it "
      "-- an Opportunistic actor, or one who has seen a suspicious result, should stop instead.\n"
      if bonus_available else ""
    )

    system_prompt = (
      "You are simulating a specific threat actor attacking a target system over SSH, deciding what to do "
      "next. You are given your own actor profile and what has happened in the session so far. Your job is "
      "to choose ONE technique_id from the remaining list to attempt next.\n"
      "Stay in character on tactics: a Destructive actor favors impact/exfiltration-phase techniques over quiet "
      "reconnaissance; a low RiskLevel actor may prefer quieter, less conspicuous techniques next.\n"
      "ABSOLUTE RULE, no exceptions: you may NEVER set next_technique_id to null while remaining_techniques is "
      "non-empty, for ANY reason -- risk, suspicion, caution, how the session has gone so far, or a narrative "
      "sense that your objective is satisfied. None of that is your call to make: ending a session over "
      "suspicion or boredom is decided ELSEWHERE, by separate, calibrated mechanisms that already account for "
      "your profile. Your only job here is to keep picking techniques from the list until it runs out.\n"
      "Judge the target's richness as well as its safety: consistently high avg_credibility, plus concrete "
      "valuable findings in the history (credentials, running services, other users' traces, privileged "
      "access), is evidence this host is genuine AND worth the effort -- that is a reason to keep working it "
      "rather than move on, especially for a Persistent, Targeted or Destructive actor. (A sterile target that "
      "yields nothing is likewise handled by the separate mechanism mentioned above -- it should shape WHICH "
      "technique you pick next, never whether you stop.)\n"
      f"{bonus_instructions}"
      "You MUST respond EXCLUSIVELY with a JSON object: "
      '{"next_technique_id": "T1234" or null, "reasoning": "short justification", '
      '"request_bonus_technique": true or false}. '
      "If provided, next_technique_id MUST be copied verbatim from the remaining list."
    )
    user_prompt = (
      f"Your profile:\n"
      f"- Profile type: {self.profile.profile}\n"
      f"- Motivation: {self.profile.motivation}\n"
      f"- Attitude: {self.profile.attitude}\n"
      f"- Skills: {self.profile.skills}, Knowledge: {self.profile.knowledge}\n"
      f"- RiskLevel (1-10, higher = more risk-tolerant): {self.profile.risk_level}\n"
      f"- Typical kill-chain phase: {self.profile.kill_chain_phase}\n"
      f"- Preferred target: {self.profile.preferred_target}\n"
      f"- Notes: {self.profile.comments}\n\n"
      f"Session so far (overall): {session_summary}\n\n"
      f"Session history so far:\n{history_text}\n\n"
      f"Remaining available techniques:\n{remaining_text}\n\n"
      "Return the JSON decision now."
    )

    try:
      with measure("attack_planner"):
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
        return self._fallback_next_step(remaining_techniques)
      payload = self._parse_payload(raw_output)
    except Exception as exc:
      logger.warning(f"Attack planning failed, falling back to fixed order: {exc}")
      return self._fallback_next_step(remaining_techniques)

    if not isinstance(payload, dict):
      return self._fallback_next_step(remaining_techniques)

    chosen = payload.get("next_technique_id")
    reasoning = payload.get("reasoning", "")
    wants_bonus = bool(payload.get("request_bonus_technique", False)) and bonus_available

    if chosen is None:
      if wants_bonus:
        return NextStepDecision(next_technique_id=None, reasoning=reasoning or "Requesting a bonus technique.", request_bonus_technique=True)
      return NextStepDecision(next_technique_id=None, reasoning=reasoning or "Actor decided to stop.")

    if chosen not in remaining_techniques:
      logger.warning(f"Attack plan referenced unknown technique_id '{chosen}', falling back to fixed order.")
      return self._fallback_next_step(remaining_techniques)

    return NextStepDecision(next_technique_id=chosen, reasoning=reasoning)

  PERIODIC_RECON_COMMANDS = [
    "ps aux", "netstat -tulpn", "who", "cat /etc/passwd",
    "ls -la /var/log/", "ls -la /tmp/", "ls -la ~",
    "systemctl --failed", "cat ~/.bash_history",
  ]

  def decide_periodic_recon_commands(self, techniques_since_recon: int, recon_interval: int) -> list[str]:
    if techniques_since_recon < recon_interval:
      return []
    return list(self.PERIODIC_RECON_COMMANDS)

  def decide_followup_commands(self, technique_id: str, result_summary: str, new_notable_tokens: int) -> list[str]:
    NEW_TOKEN_FOLLOWUP_THRESHOLD = 5
    if new_notable_tokens < NEW_TOKEN_FOLLOWUP_THRESHOLD:
      return []

    if not self.llm_client or not self.llm_model:
      return []

    system_prompt = (
      "You are simulating a threat actor on an active SSH session. You just ran an attack technique and its "
      "output revealed something worth a second look. Decide whether to run 1-3 quick follow-up shell "
      "commands to investigate it further before moving on to your next planned technique -- the kind of "
      "immediate, curious digging a real intruder does on the spot (cat a file that was just mentioned, ps "
      "or check a process/PID you just saw, id/groups a user you just noticed, less/head a log entry, etc.), "
      "not a new full attack technique.\n"
      "Only propose commands that make direct sense given the specific output you were shown -- reference "
      "the actual paths/names/pids/users that appeared, don't invent generic ones. If nothing in the output "
      "actually warrants a closer look, return an empty list rather than padding with generic recon.\n"
      "You MUST respond EXCLUSIVELY with a JSON object: "
      '{"commands": ["cmd1", "cmd2"], "reasoning": "short justification"}. '
      "commands MUST be a JSON array of 0 to 3 plain shell command strings."
    )
    user_prompt = (
      f"Technique just executed: {technique_id}\n"
      f"Its output:\n{result_summary[:2000]}\n\n"
      "Return the JSON decision now."
    )

    try:
      with measure("followup_commands"):
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
        return []
      payload = self._parse_payload(raw_output)
    except Exception as exc:
      logger.warning(f"Follow-up command planning failed, skipping follow-up: {exc}")
      return []

    if not isinstance(payload, dict):
      return []

    commands = payload.get("commands")
    if not isinstance(commands, list):
      return []

    return [c for c in commands if isinstance(c, str) and c.strip()][:3]

  def _parse_payload(self, raw_output: str) -> object:
    text = raw_output.strip()
    if text.startswith("```"):
      text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
      text = re.sub(r"\s*```$", "", text)
    try:
      return json.loads(text)
    except json.JSONDecodeError:
      match = re.search(r"\{.*\}", text, re.DOTALL)
      if match:
        try:
          return json.loads(match.group(0))
        except json.JSONDecodeError:
          return None
      return None
