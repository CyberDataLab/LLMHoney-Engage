"""Data models of the defender telemetry."""

from datetime import datetime

from pydantic import BaseModel, Field

from src.honeyengage.engage_engine.engage_mapping import EngageResult


class NetworkInfo(BaseModel):
    source_ip: str = Field(..., description="The source IP address")
    source_port: int = Field(..., description="The source port number")
    ssh_client: str = Field(..., description="The SSH client used by the client")

class EnvironmentInfo(BaseModel):
    terminal_type: str = Field(..., description="The type of terminal used by the client")
    shell_width: int = Field(..., description="The width of the client's terminal")
    shell_height: int = Field(..., description="The height of the client's terminal")

class AuthenticationInfo(BaseModel):
    username: str = Field(..., description="The username used for authentication")
    password: str = Field(..., description="The password used for authentication")
    timestamp: datetime = Field(..., description="The timestamp of the authentication attempt")

class MitreMappingError(BaseModel):
    error_type: str = Field(..., description="The type of error encountered during MITRE mapping evaluation")
    error_message: str = Field(..., description="A descriptive message explaining the error encountered during MITRE mapping evaluation")

class MitreMapping(BaseModel):
    technique_id: str = Field(..., description="The MITRE technique ID associated with the command")
    confidence: float = Field(..., description="The confidence score of the MITRE mapping (between 0 and 1)")
    cti_sentence: str = Field(..., description="A sentence describing the mapping to the MITRE technique")

class InteractionInfo(BaseModel):
    command: str = Field(..., description="The command executed by the client")
    timestamp: datetime = Field(..., description="The timestamp of the command execution")
    backspaces: int = Field(..., description="The number of backspaces used in the command")
    response: str | None = Field(None, description="The raw output HoneyEngage sent back to the client for this command, if captured")
    mitre_mapping: MitreMapping | None = Field(None, description="The MITRE mapping associated with the command, if any")
    engage_details: EngageResult | None = Field(None, description="The Engage details associated with the command, if any")
    response_latency_seconds: float | None = Field(
        None,
        description=(
            "Wall-clock seconds between the server receiving this command and finishing "
            "shell.execute_command() for it (before the response is sent back over the "
            "channel). Captured to diagnose attacker-side 'Socket is closed' disconnects "
            "that correlate with slow server-side responses under load."
        ),
    )

class SessionInfo(BaseModel):
    start_time: datetime = Field(..., description="The start time of the session")
    end_time: datetime | None = Field(..., description="The end time of the session")
    total_commands: int = Field(..., description="The total number of commands executed during the session")
    exit_reason: str | None = Field(..., description="The reason for session termination (e.g., client disconnect, logout command, etc.)")

class Session(BaseModel):
    session_id: str = Field(..., description="The ID of the session")
    network: NetworkInfo = Field(..., description="The network information of the session")
    environment: EnvironmentInfo = Field(..., description="The environment information of the session")
    authentication: AuthenticationInfo = Field(..., description="The authentication information of the session")
    interactions: list[InteractionInfo] = Field(..., description="The list of interactions during the session")
    session_metadata: SessionInfo = Field(..., description="The metadata of the session")