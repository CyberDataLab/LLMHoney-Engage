import pytest

from src.llmattacker.threat_actor.profile import THREAT_ACTOR_PROFILES, pick_threat_actor_profile


class TestThreatActorProfileCatalog:
  def test_every_profile_has_internally_consistent_required_fields(self):
    for profile in THREAT_ACTOR_PROFILES.values():
      assert profile.profile_id
      assert 0 <= profile.automation_level <= 2
      assert 1 <= profile.risk_level <= 10
      assert profile.profile
      assert profile.motivation
      assert profile.skills
      assert profile.knowledge
      assert profile.attitude

  def test_profile_ids_match_their_dict_keys(self):
    for key, profile in THREAT_ACTOR_PROFILES.items():
      assert key == profile.profile_id

  def test_catalog_has_multiple_distinct_profiles(self):
    assert len(THREAT_ACTOR_PROFILES) >= 5


class TestPickThreatActorProfile:
  def test_forced_profile_id_is_honored(self):
    profile = pick_threat_actor_profile("any-session", forced_profile_id="nation_state_spy")
    assert profile.profile_id == "nation_state_spy"

  def test_unknown_forced_profile_id_falls_back_to_random_choice(self):
    profile = pick_threat_actor_profile("any-session", forced_profile_id="not_a_real_profile")
    assert profile.profile_id in THREAT_ACTOR_PROFILES

  def test_same_seed_and_session_id_picks_the_same_profile(self):
    first = pick_threat_actor_profile("session-a", base_seed=42)
    second = pick_threat_actor_profile("session-a", base_seed=42)
    assert first.profile_id == second.profile_id

  def test_different_session_ids_can_pick_different_profiles(self):
    profiles = {pick_threat_actor_profile(f"session-{i}", base_seed=42).profile_id for i in range(20)}
    assert len(profiles) > 1

  def test_no_base_seed_is_non_deterministic_safe_default(self):
    profile = pick_threat_actor_profile("session-x", base_seed=None)
    assert profile.profile_id in THREAT_ACTOR_PROFILES


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
