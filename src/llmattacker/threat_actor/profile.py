"""Threat actor profiles (motivation, attitude, risk tolerance, and other attributes) and skill levels."""

import hashlib
import random

from pydantic import BaseModel, Field


class ThreatActorProfile(BaseModel):
  profile_id: str = Field(..., description="Stable identifier for this curated profile (e.g. 'nation_state_spy')")
  country: str = Field(..., description="Attacker's claimed/assumed country of origin")
  automation_level: int = Field(..., ge=0, le=2, description="0=manual, 1=semi-automated, 2=fully scripted/automated")
  evasion: str = Field(..., description="Typical evasion posture, e.g. 'None', 'Basic', 'Advanced'")
  kill_chain_phase: str = Field(..., description="The MITRE ATT&CK kill-chain phase this actor is typically operating in")
  risk_level: int = Field(..., ge=1, le=10, description="Self-assessed operational risk tolerance/aggressiveness, 1-10")
  profile: str = Field(..., description="Actor category: activist, competitor, crime-syndicate, criminal, insider-accidental, insider-disgruntled, nation-state, spy")
  motivation: str = Field(..., description="Espionage, Financial, Ideology, Notoriety, Sabotage")
  skills: str = Field(..., description="Basic, Intermediate, Advanced, Expert")
  knowledge: str = Field(..., description="Low, Moderate")
  affiliation: str = Field(..., description="Criminal-Enterprise, Hacktivist, Insider, State, State-Contractor, Unknown")
  attitude: str = Field(..., description="Destructive, Opportunistic, Persistent, Targeted")
  threat_group: str = Field(default="Unknown", description="Named or generic threat-group label this actor is playing")
  preferred_target: str = Field(..., description="What this actor is primarily after, e.g. 'credentials', 'data exfiltration', 'persistence footholds'")
  comments: str = Field(default="", description="Free-text notes on this profile's intended behavior, for prompt context")


THREAT_ACTOR_PROFILES: dict[str, ThreatActorProfile] = {
  "script_kiddie": ThreatActorProfile(
    profile_id="script_kiddie",
    country="Unknown", automation_level=2, evasion="None", kill_chain_phase="reconnaissance",
    risk_level=3, profile="activist", motivation="Notoriety", skills="Basic", knowledge="Low",
    affiliation="Unknown", attitude="Opportunistic", threat_group="Unknown",
    preferred_target="easy, publicly-known vulnerabilities", comments="Runs canned scripts, gives up quickly if a command fails, noisy and unconcerned with detection.",
  ),
  "financially_motivated_criminal": ThreatActorProfile(
    profile_id="financially_motivated_criminal",
    country="Unknown", automation_level=1, evasion="Basic", kill_chain_phase="credential-access",
    risk_level=6, profile="criminal", motivation="Financial", skills="Intermediate", knowledge="Moderate",
    affiliation="Criminal-Enterprise", attitude="Opportunistic", threat_group="Generic-Crimeware",
    preferred_target="credentials, financial data, ransomable assets", comments="Efficient and pragmatic; abandons a target quickly if it looks unprofitable or well-defended.",
  ),
  "ransomware_operator": ThreatActorProfile(
    profile_id="ransomware_operator",
    country="Unknown", automation_level=2, evasion="Basic", kill_chain_phase="impact",
    risk_level=8, profile="crime-syndicate", motivation="Financial", skills="Advanced", knowledge="Moderate",
    affiliation="Criminal-Enterprise", attitude="Destructive", threat_group="Generic-Ransomware-Crew",
    preferred_target="backups, high-value data for encryption/exfiltration leverage", comments="Aggressive and fast-moving once inside; prioritizes locating and disabling backups.",
  ),
  "corporate_insider": ThreatActorProfile(
    profile_id="corporate_insider",
    country="Unknown", automation_level=0, evasion="None", kill_chain_phase="collection",
    risk_level=4, profile="insider-disgruntled", motivation="Sabotage", skills="Intermediate", knowledge="Moderate",
    affiliation="Insider", attitude="Targeted", threat_group="Unknown",
    preferred_target="specific internal data or systems tied to a personal grievance", comments="Already has some legitimate access context; behaves cautiously to avoid immediate suspicion.",
  ),
  "corporate_spy": ThreatActorProfile(
    profile_id="corporate_spy",
    country="Unknown", automation_level=1, evasion="Advanced", kill_chain_phase="collection",
    risk_level=5, profile="competitor", motivation="Espionage", skills="Advanced", knowledge="Moderate",
    affiliation="Unknown", attitude="Persistent", threat_group="Unknown",
    preferred_target="proprietary/confidential business data", comments="Patient and quiet; avoids destructive actions that would trigger incident response.",
  ),
  "hacktivist": ThreatActorProfile(
    profile_id="hacktivist",
    country="Unknown", automation_level=1, evasion="None", kill_chain_phase="impact",
    risk_level=7, profile="activist", motivation="Ideology", skills="Intermediate", knowledge="Low",
    affiliation="Hacktivist", attitude="Destructive", threat_group="Generic-Hacktivist-Collective",
    preferred_target="defacement, public data leaks, service disruption", comments="Wants visible impact and public attribution; unconcerned with stealth.",
  ),
  "nation_state_spy": ThreatActorProfile(
    profile_id="nation_state_spy",
    country="Unknown", automation_level=1, evasion="Advanced", kill_chain_phase="persistence",
    risk_level=9, profile="nation-state", motivation="Espionage", skills="Expert", knowledge="Moderate",
    affiliation="State", attitude="Persistent", threat_group="Generic-APT",
    preferred_target="long-term persistence, strategic intelligence, credentials", comments="Extremely patient and methodical; avoids any action that risks premature discovery, prioritizes maintaining access over immediate gain.",
  ),
  "nation_state_saboteur": ThreatActorProfile(
    profile_id="nation_state_saboteur",
    country="Unknown", automation_level=2, evasion="Advanced", kill_chain_phase="impact",
    risk_level=10, profile="nation-state", motivation="Sabotage", skills="Expert", knowledge="Moderate",
    affiliation="State-Contractor", attitude="Destructive", threat_group="Generic-APT",
    preferred_target="critical infrastructure disruption, destructive payloads", comments="Highly capable and willing to accept detection risk once the objective is in reach.",
  ),
}


def resolve_profile_seed(session_id: str, base_seed: str | int | None) -> random.Random:
  if base_seed is None:
    return random.Random()
  digest = hashlib.sha256(f"{base_seed}:threat_actor_profile:{session_id}".encode()).hexdigest()
  return random.Random(int(digest, 16))


def pick_threat_actor_profile(
  session_id: str, forced_profile_id: str | None = None, base_seed: str | int | None = None
) -> ThreatActorProfile:
  if forced_profile_id:
    profile = THREAT_ACTOR_PROFILES.get(forced_profile_id)
    if profile is not None:
      return profile
  rng = resolve_profile_seed(session_id, base_seed)
  return rng.choice(list(THREAT_ACTOR_PROFILES.values()))
