import pytest

from orchestrator.technique_pool import (
  DEFAULT_SAMPLE_SIZE,
  LEVEL_TACTICS,
  build_technique_pools,
  sample_techniques_for_level,
)


@pytest.fixture(scope="module")
def pools():
  return build_technique_pools()


class TestBuildTechniquePools:
  def test_every_level_has_a_non_empty_pool(self, pools):
    for level in LEVEL_TACTICS:
      assert pools[level], f"{level} pool is empty"

  def test_pools_only_contain_technique_ids_with_atomics_available(self, pools):
    import os

    from orchestrator.technique_pool import ATOMICS_DIR
    available = {d for d in os.listdir(ATOMICS_DIR) if d.startswith("T")}
    for techniques in pools.values():
      assert set(techniques).issubset(available)

  def test_levels_can_overlap_but_pools_are_not_identical(self, pools):
    assert pools["Beginner"] != pools["Intermediate"]
    assert pools["Intermediate"] != pools["Advanced"]


class TestSampleTechniquesForLevel:
  def test_same_seed_and_iteration_reproduces_the_same_sample(self, pools):
    first = sample_techniques_for_level("Intermediate", iteration=0, seed=42, pools=pools)
    second = sample_techniques_for_level("Intermediate", iteration=0, seed=42, pools=pools)
    assert first == second

  def test_different_iterations_can_sample_different_techniques(self, pools):
    samples = [
      tuple(sample_techniques_for_level("Advanced", iteration=i, seed=42, pools=pools))
      for i in range(5)
    ]
    assert len(set(samples)) > 1

  def test_different_seeds_can_sample_different_techniques(self, pools):
    a = sample_techniques_for_level("Advanced", iteration=0, seed=1, pools=pools)
    b = sample_techniques_for_level("Advanced", iteration=0, seed=2, pools=pools)
    assert a != b

  def test_sample_size_matches_default_for_level(self, pools):
    for level, expected_size in DEFAULT_SAMPLE_SIZE.items():
      sample = sample_techniques_for_level(level, iteration=0, seed=1, pools=pools)
      assert len(sample) == min(expected_size, len(pools[level]))

  def test_explicit_sample_size_overrides_default(self, pools):
    sample = sample_techniques_for_level("Advanced", iteration=0, seed=1, sample_size=2, pools=pools)
    assert len(sample) == 2

  def test_sample_size_larger_than_pool_is_capped(self, pools):
    tiny_pool = {"Beginner": ["T1057"]}
    sample = sample_techniques_for_level("Beginner", iteration=0, seed=1, sample_size=10, pools=tiny_pool)
    assert sample == ["T1057"]

  def test_sampled_techniques_are_distinct(self, pools):
    sample = sample_techniques_for_level("Advanced", iteration=0, seed=1, pools=pools)
    assert len(sample) == len(set(sample))

  def test_unknown_level_returns_empty_list(self, pools):
    assert sample_techniques_for_level("Nonexistent", iteration=0, seed=1, pools=pools) == []


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
