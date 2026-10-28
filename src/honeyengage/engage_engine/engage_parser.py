"""Loads the official MITRE Engage dataset."""

import json
from pathlib import Path
from typing import Any

import pandas as pd
from loguru import logger

from src.honeyengage.engage_engine.engage_mapping import (
  EngageActivity,
  EngageApproach,
  EngageDetails,
  EngageGoal,
  EngageVulnerability,
  TechniqueMapping,
)

logger.add("logs/honeyengage_engage_engine.log", rotation="10 MB")

class EngageParser:
  def __init__(self, engage_data_file: str = "src/honeyengage/engage_engine/Engage-Data-V1.0.xlsx", cache_path: str | None = None):
    self.engage_data_file = engage_data_file
    self.cache_path = Path(cache_path or Path(engage_data_file).with_name("engage_mapping_cache.json"))
    self.mapper = self.build_engage_mapping(engage_data_file)

  @staticmethod
  def _normalize(value: Any) -> str:
    if pd.isna(value):
      return ""
    return str(value).strip()

  def _find_row_by_id(self, dataframe: pd.DataFrame, identifier: str, column_index: int = 0) -> pd.Series:
    normalized_identifier = self._normalize(identifier)
    if not normalized_identifier:
      raise ValueError("Empty identifier provided")

    matches = dataframe[dataframe.iloc[:, column_index].apply(self._normalize) == normalized_identifier]
    if matches.empty:
      raise ValueError(f"Unable to find {normalized_identifier} in Engage workbook")

    return matches.iloc[0]

  @staticmethod
  def _dump_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
      return model.model_dump()
    return model.dict()

  def _load_mapper_cache(self) -> dict[str, TechniqueMapping]:
    if not self.cache_path.exists():
      return {}

    with self.cache_path.open("r", encoding="utf-8") as cache_file:
      cached_payload = json.load(cache_file)

    mapper: dict[str, TechniqueMapping] = {}
    for technique_id, mapping_data in cached_payload.items():
      engage_details = [EngageDetails(**engage_detail) for engage_detail in mapping_data.get("engage_details", [])]
      mapper[technique_id] = TechniqueMapping(
        technique_id=mapping_data.get("technique_id", technique_id),
        engage_details=engage_details,
      )

    return mapper

  def _save_mapper_cache(self, mapper: dict[str, TechniqueMapping]) -> None:
    cache_payload: dict[str, Any] = {}
    for technique_id, mapping in mapper.items():
      cache_payload[technique_id] = {
        "technique_id": mapping.technique_id,
        "engage_details": [self._dump_model(engage_detail) for engage_detail in mapping.engage_details],
      }

    self.cache_path.parent.mkdir(parents=True, exist_ok=True)
    with self.cache_path.open("w", encoding="utf-8") as cache_file:
      json.dump(cache_payload, cache_file, indent=2)

  def build_engage_details(self, activity_id: str, vulnerability_id: str, excel_path: str) -> EngageDetails:

    activity_row = self._find_row_by_id(self.df_activities, activity_id)
    vulnerability_row = self._find_row_by_id(self.df_vulnerabilities, vulnerability_id)

    activity_matches = self.df_approach_activity_mapping[
      self.df_approach_activity_mapping.iloc[:, 1].apply(self._normalize) == self._normalize(activity_id)
    ]
    if activity_matches.empty:
      raise ValueError(f"No approach mapped to activity {activity_id}")

    approach_id = self._normalize(activity_matches.iloc[0, 0])
    approach_row = self._find_row_by_id(self.df_approaches, approach_id)

    goal_matches = self.df_goal_approach_mapping[
      self.df_goal_approach_mapping.iloc[:, 1].apply(self._normalize) == approach_id
    ]
    if goal_matches.empty:
      raise ValueError(f"No goal mapped to approach {approach_id}")

    goal_id = self._normalize(goal_matches.iloc[0, 0])
    goal_row = self._find_row_by_id(self.df_goals, goal_id)

    return EngageDetails(
      goal=EngageGoal(
        goal_id=self._normalize(goal_row.iloc[0]),
        name=self._normalize(goal_row.iloc[1]),
        short_description=self._normalize(goal_row.iloc[2]),
        long_description=self._normalize(goal_row.iloc[3]),
      ),
      approach=EngageApproach(
        approach_id=self._normalize(approach_row.iloc[0]),
        name=self._normalize(approach_row.iloc[1]),
        short_description=self._normalize(approach_row.iloc[2]),
        long_description=self._normalize(approach_row.iloc[3]),
      ),
      activity=EngageActivity(
        activity_id=self._normalize(activity_row.iloc[0]),
        name=self._normalize(activity_row.iloc[1]),
        short_description=self._normalize(activity_row.iloc[2]),
        long_description=self._normalize(activity_row.iloc[3]),
      ),
      vulnerability=EngageVulnerability(
        vulnerability_id=self._normalize(vulnerability_row.iloc[0]),
        description=self._normalize(vulnerability_row.iloc[1]),
      ),
    )

  def build_engage_mapping(self, excel_path: str) -> dict[str, TechniqueMapping]:
    cached_mapper = self._load_mapper_cache()
    if cached_mapper:
      return cached_mapper

    try:
      self.df_enterprise = pd.read_excel(excel_path, sheet_name="Enterprise ATT&CK Mappings")
      self.df_goals = pd.read_excel(excel_path, sheet_name="Goals")
      self.df_approaches = pd.read_excel(excel_path, sheet_name="Approaches")
      self.df_activities = pd.read_excel(excel_path, sheet_name="Activities")
      self.df_vulnerabilities = pd.read_excel(excel_path, sheet_name="Vulnerabilities")
      self.df_approach_activity_mapping = pd.read_excel(excel_path, sheet_name="Approach Activity Mappings")
      self.df_goal_approach_mapping = pd.read_excel(excel_path, sheet_name="Goal Approach Mappings")

      mapper: dict[str, TechniqueMapping] = {}
      for _, row in self.df_enterprise.iterrows():
        attack_id = str(row.get("attack_id", "")).strip()
        eav_id = str(row.get("eav_id", "")).strip()
        eac_id = str(row.get("eac_id", "")).strip()

        if not attack_id or attack_id.lower() == "nan" or not eac_id or eac_id.lower() == "nan" or not eav_id or eav_id.lower() == "nan":
          continue

        mapping = TechniqueMapping(
          technique_id=attack_id,
          engage_details=[]
        )
        
        if attack_id not in mapper:
          mapper[attack_id] = mapping

        engage_data = self.build_engage_details(eac_id, eav_id, excel_path)

        if engage_data not in mapper[attack_id].engage_details:
          mapper[attack_id].engage_details.append(engage_data)
          
      
      self._save_mapper_cache(mapper)
      logger.success(f"Loaded {len(mapper)} ATT&CK techniques from Engage data.")
      return mapper
    except Exception as e:
      logger.error(f"Error loading Engage data: {e}")
      return {}
  
  def get_engage_activities_for_technique(self, technique_id: str) -> list[EngageDetails]:
    technique_mapping = self.mapper.get(technique_id)
    if technique_mapping is None:
      return []
    return technique_mapping.engage_details

if __name__ == "__main__":
  mapper = EngageParser()
  
  detected_technique = "T1003"
  activities = mapper.get_engage_activities_for_technique(detected_technique)
  
  print(f"For technique {detected_technique}, MITRE Engage suggests:")
  for act in activities:
    print(f" - Goal: [{act.goal.goal_id}] {act.goal.name}")
    print(f"   Approach: [{act.approach.approach_id}] {act.approach.name}")
    print(f"   Activity: [{act.activity.activity_id}] {act.activity.name}")
    print(f"   Vulnerability: [{act.vulnerability.vulnerability_id}] {act.vulnerability.description}")