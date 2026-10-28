"""Data models of the post-hoc session evaluation."""

from pydantic import BaseModel, Field


class CommandVerdict(BaseModel):
  command: str = Field(..., description="The command that was executed against HoneyEngage")
  response: str | None = Field(..., description="The output HoneyEngage returned for this command, if captured")
  predicted_technique: str | None = Field(None, description="The ATT&CK technique HoneyEngage's own correlation engine mapped this command to, if any")
  engage_capabilities_used: list[str] = Field(default_factory=list, description="Deception capabilities HoneyEngage deployed in reaction to this command")
  credibility_score: float = Field(..., description="Judge's credibility score for this single command/response pair (0.0 = obviously fake, 1.0 = fully credible)")
  reasoning: str = Field(..., description="The judge's stated reasoning for the score")
  judge_error: bool = Field(False, description="True if the judge LLM call failed or returned unusable output for this command")


class SessionVerdict(BaseModel):
  session_id: str = Field(..., description="The HoneyEngage session_id this verdict covers")
  attacker_tool: str = Field(..., description="Name of the tool that generated the attack traffic (e.g. llmattacker, hackingbuddygpt, manual)")
  total_commands_judged: int = Field(..., description="How many command/response pairs were evaluated")
  average_credibility: float = Field(..., description="Mean credibility score across all judged commands")
  detected_honeypot: bool = Field(..., description="True if average_credibility fell below the configured detection threshold")
  lowest_scoring_command: CommandVerdict | None = Field(None, description="The single most honeypot-revealing command/response pair, if any were judged")
  command_verdicts: list[CommandVerdict] = Field(default_factory=list, description="Per-command verdicts, in session order")
