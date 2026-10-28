"""Machine personas: the six server roles the host can claim, with their packages, services, and compatible scenarios."""

import hashlib
import os
import random

from pydantic import BaseModel, Field


class MachineRole(BaseModel):
  role_id: str = Field(..., description="Stable identifier for this role (e.g. 'web_server')")
  display_name: str = Field(..., description="Human-readable name (e.g. 'LAMP web server')")
  typical_packages: list[tuple[str, str, str]] = Field(
    ..., description="List of (package_name, version, description) plausible for this role"
  )
  typical_ports: list[tuple[int, str]] = Field(
    ..., description="List of (port, protocol_service_name) this role would plausibly have listening"
  )
  compatible_scenario_tags: list[str] = Field(
    default_factory=list, description="Scenario template tags (see scenario_catalog.py) that make sense for this role"
  )


NEUTRAL_ROLE = MachineRole(
  role_id="neutral",
  display_name="Bare Ubuntu server (no distinguishing services)",
  typical_packages=[],
  typical_ports=[],
  compatible_scenario_tags=[],
)
"""A deliberately featureless role used as the experimental control for the
machine-persona ablation (HONEYENGAGE_PERSONA_MODE=none): no extra packages,
ports, or scenario tags, so deception responses fall back to whatever they
would have produced before machine personas existed. Comparing sessions run
under this role against sessions using a real MACHINE_ROLES entry isolates
the contribution of persona-driven contextual coherence."""

MACHINE_ROLES: dict[str, MachineRole] = {
  "web_server": MachineRole(
    role_id="web_server",
    display_name="LAMP web server",
    typical_packages=[
      ("apache2", "2.4.52-1ubuntu4.10", "Apache HTTP Server"),
      ("php8.1-fpm", "8.1.2-1ubuntu2.20", "server-side, HTML-embedded scripting language (FPM-CGI binary)"),
      ("mysql-server", "8.0.36-0ubuntu0.22.04.1", "MySQL database server"),
      ("certbot", "1.21.0-1ubuntu0.1", "automatically configure HTTPS using Let's Encrypt"),
    ],
    typical_ports=[(80, "http"), (443, "https"), (3306, "mysql")],
    compatible_scenario_tags=["web_app", "database", "credentials", "backup"],
  ),
  "database_server": MachineRole(
    role_id="database_server",
    display_name="Dedicated database server",
    typical_packages=[
      ("postgresql-14", "14.11-0ubuntu0.22.04.1", "object-relational SQL database"),
      ("pgbouncer", "1.16.1-1", "lightweight connection pooler for PostgreSQL"),
      ("redis-server", "6.0.16-1ubuntu0.2", "Persistent key-value database"),
    ],
    typical_ports=[(5432, "postgresql"), (6379, "redis")],
    compatible_scenario_tags=["database", "credentials", "backup"],
  ),
  "ci_runner": MachineRole(
    role_id="ci_runner",
    display_name="CI/CD build runner",
    typical_packages=[
      ("docker-ce", "5:24.0.7-1~ubuntu.22.04~jammy", "Docker: the open-source application container engine"),
      ("git", "1:2.34.1-1ubuntu1.11", "fast, scalable, distributed revision control system"),
      ("jenkins", "2.426.3", "Jenkins Automation Server"),
    ],
    typical_ports=[(8080, "jenkins"), (2376, "docker")],
    compatible_scenario_tags=["credentials", "ci_cd", "backup"],
  ),
  "file_server": MachineRole(
    role_id="file_server",
    display_name="Internal file/backup server",
    typical_packages=[
      ("samba", "4.15.13+dfsg-0ubuntu1.6", "SMB/CIFS file, print, and login server"),
      ("nfs-kernel-server", "1:2.6.1-1ubuntu1.2", "support for NFS kernel server"),
      ("restic", "0.16.2-1", "backup program with compression, encryption and de-duplication"),
    ],
    typical_ports=[(445, "microsoft-ds"), (2049, "nfs")],
    compatible_scenario_tags=["backup", "credentials"],
  ),
  "mail_relay": MachineRole(
    role_id="mail_relay",
    display_name="Outbound mail relay",
    typical_packages=[
      ("postfix", "3.6.4-1ubuntu1.5", "High-performance mail transport agent"),
      ("dovecot-core", "1:2.3.16-1.2ubuntu2.3", "secure POP3/IMAP server"),
      ("opendkim", "2.10.3-1.1ubuntu0.1", "DKIM signing and verification"),
    ],
    typical_ports=[(25, "smtp"), (587, "submission"), (143, "imap")],
    compatible_scenario_tags=["email", "credentials"],
  ),
  "workstation": MachineRole(
    role_id="workstation",
    display_name="Developer workstation",
    typical_packages=[
      ("code", "1.85.2-1700071133", "Visual Studio Code"),
      ("python3-pip", "22.0.2+dfsg-1ubuntu0.5", "Python package installer"),
      ("openvpn", "2.5.5-1ubuntu3.5", "virtual private network daemon"),
    ],
    typical_ports=[(1194, "openvpn")],
    compatible_scenario_tags=["credentials", "ci_cd"],
  ),
}


def resolve_persona_seed(session_id: str) -> random.Random:
  base_seed = os.getenv("HONEYENGAGE_SEED")
  if base_seed is None:
    return random.Random()
  digest = hashlib.sha256(f"{base_seed}:persona:{session_id}".encode()).hexdigest()
  return random.Random(int(digest, 16))


def pick_machine_role(session_id: str, forced_role_id: str | None = None) -> MachineRole:
  if os.getenv("HONEYENGAGE_PERSONA_MODE", "random").lower() == "none":
    return NEUTRAL_ROLE

  if forced_role_id:
    role = MACHINE_ROLES.get(forced_role_id)
    if role is not None:
      return role
  rng = resolve_persona_seed(session_id)
  return rng.choice(list(MACHINE_ROLES.values()))
