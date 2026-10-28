"""Mapping from ATT&CK techniques to MITRE Engage activities."""

from pydantic import BaseModel, Field


class EngageStepResult(BaseModel):
  result_status: str = Field(..., description="The result state of this step's execution (e.g., success, failure, error)")
  capability_name: str = Field(..., description="The name of the Engage capability that was executed for this step")
  eac_id: str = Field(..., description="The Engage Activity ID (e.g., EAC-001) associated with this step")
  error_message: str = Field(..., description="Error message if this step's execution failed")

class EngageResult(BaseModel):
  result_status: str = Field(..., description="Summary result state for the whole chain: success if every step succeeded, otherwise the first failure encountered")
  capability_name: str = Field(..., description="The name of the last capability executed in the chain (kept for backwards compatibility with single-step consumers)")
  eac_id: str = Field(..., description="The Engage Activity ID (e.g., EAC-001) associated with the executed chain")
  error_message: str = Field(..., description="Error message from the first failed step, if any")
  steps: list[EngageStepResult] = Field(default_factory=list, description="Every capability executed as part of this Course of Action, in execution order")
  plan_reasoning: str = Field(default="", description="The engage LLM's stated reasoning for choosing this chain of capabilities")

class EngageGoal(BaseModel):
  goal_id: str = Field(..., description="The Engage Goal ID (e.g., EAG-001)")
  name: str = Field(..., description="The Engage Goal name")
  short_description: str = Field(..., description="The Engage Goal short description")
  long_description: str = Field(..., description="The Engage Goal long description")

class EngageApproach(BaseModel):
  approach_id: str = Field(..., description="The Engage Approach ID (e.g., EAP-001)")
  name: str = Field(..., description="The Engage Approach name")
  short_description: str = Field(..., description="The Engage Approach short description")
  long_description: str = Field(..., description="The Engage Approach long description")

class EngageActivity(BaseModel):
  activity_id: str = Field(..., description="The Engage Activity ID (e.g., EAC-001)")
  name: str = Field(..., description="The Engage Activity name")
  short_description: str = Field(..., description="The Engage Activity short description")
  long_description: str = Field(..., description="The Engage Activity long description")

class EngageVulnerability(BaseModel):
  vulnerability_id: str = Field(..., description="The Engage Vulnerability ID (e.g., EV-001)")
  description: str = Field(..., description="The Engage Vulnerability description")

class EngageDetails(BaseModel):
  goal: EngageGoal = Field(..., description="The Engage Goal associated with this technique")
  approach: EngageApproach = Field(..., description="The Engage Approach associated with this technique")
  activity: EngageActivity = Field(..., description="The Engage Activity associated with this technique")
  vulnerability: EngageVulnerability = Field(..., description="The Engage Vulnerability associated with this technique")

class TechniqueMapping(BaseModel):
  technique_id: str = Field(..., description="The MITRE ATT&CK Technique ID (e.g., T1003)")
  engage_details: list[EngageDetails] = Field(..., description="List of Engage details associated with this technique")