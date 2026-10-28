"""Catalogue of the 57 scenario templates: Engage activity, ordered capability chain, narrative, and compatible machine roles."""

from pydantic import BaseModel, Field


class ScenarioTemplate(BaseModel):
  scenario_id: str = Field(..., description="Stable identifier, e.g. 'lures_aws_creds_with_backup_log'")
  eac_id: str = Field(..., description="The Engage Activity ID this scenario is a curated response for")
  narrative: str = Field(..., description="One-line human-readable description of the story this scenario tells")
  capability_chain: list[str] = Field(..., description="Capability class names to execute, in order")
  compatible_roles: list[str] = Field(
    default_factory=list,
    description="MachineRole role_ids this scenario fits (e.g. ['web_server', 'database_server']); empty means 'fits any role'",
  )

  def fits_role(self, role_id: str) -> bool:
    return not self.compatible_roles or role_id in self.compatible_roles


_LURES = [
  ScenarioTemplate(scenario_id="lures_01", eac_id="EAC0005", narrative="Fake AWS credentials paired with a matching backup log entry and the process that would use them",
    capability_chain=["CreateFakeAWSCredentialsCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_02", eac_id="EAC0005", narrative="Stale admin account with weak shell history, a planted SSH key, and a log entry from its last use",
    capability_chain=["CreateFakeUserAccountCapability", "ModifyBashHistoryCapability", "PlantSshAuthorizedKeyCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_03", eac_id="EAC0005", narrative="Decoy cron backup script, the temp dump file it supposedly produced, a log entry noting the run, and the process that scheduled it",
    capability_chain=["CreateFileCapability", "GenerateTemporalFilesCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=["file_server", "database_server", "web_server"]),
  ScenarioTemplate(scenario_id="lures_04", eac_id="EAC0005", narrative="Fake internal service process, the network connection it would hold open, and a log entry marking its startup",
    capability_chain=["InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_05", eac_id="EAC0005", narrative="A /etc/hosts entry for a fake internal host, a log referencing it, and the connection actually reaching it",
    capability_chain=["ModifyHostsFileCapability", "CreateLogFileCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_06", eac_id="EAC0005", narrative="Forgotten personal dotfiles, stray temp files, and an environment variable left set from a prior session",
    capability_chain=["GenerateUserDotFilesCapability", "GenerateTemporalFilesCapability", "AddEnviromentVariableCapability"], compatible_roles=["workstation", "ci_runner"]),
  ScenarioTemplate(scenario_id="lures_07", eac_id="EAC0005", narrative="A leftover config file quietly modified to look tampered-with, a log noting the change, and a process still running off it",
    capability_chain=["ModifyFileContentCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_08", eac_id="EAC0005", narrative="A recently 'deleted' sensitive file whose metadata still lingers, with a log entry from whoever removed it",
    capability_chain=["DeleteFileCapability", "ModifyFileMetadataCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_09", eac_id="EAC0005", narrative="Full identity bait: fake account, matching AWS keys, a process using them, and the connection it opens",
    capability_chain=["CreateFakeUserAccountCapability", "CreateFakeAWSCredentialsCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_10", eac_id="EAC0005", narrative="An unexplained temp file, a log line hinting at the job that dropped it, a dotfile trail back to whoever ran it, and their leftover env var",
    capability_chain=["GenerateTemporalFilesCapability", "CreateLogFileCapability", "GenerateUserDotFilesCapability", "AddEnviromentVariableCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_11", eac_id="EAC0005", narrative="Persistent access left by a prior party: a planted SSH key, the sudo command they used to get in, a log entry of the session, and the account they were operating as",
    capability_chain=["PlantSshAuthorizedKeyCapability", "SimulateSudoAbuseCapability", "CreateLogFileCapability", "CreateFakeUserAccountCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="lures_12", eac_id="EAC0005", narrative="Evidence someone already logged in, failed a few attempts first, then escalated privileges here recently",
    capability_chain=["SimulateFailedLoginAttemptsCapability", "SimulateSudoAbuseCapability", "CreateLogFileCapability"], compatible_roles=[]),
]

_BURN_IN = [
  ScenarioTemplate(scenario_id="burnin_01", eac_id="EAC0008", narrative="Routine log rotation, a leftover temp file, and the dotfiles of whoever last touched it, like normal system churn",
    capability_chain=["CreateLogFileCapability", "GenerateTemporalFilesCapability", "GenerateUserDotFilesCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="burnin_02", eac_id="EAC0008", narrative="A newly-created scratch file mid-edit, its timestamps freshly touched, a log entry from the editor session, and the process still holding it open",
    capability_chain=["CreateFileCapability", "ModifyFileMetadataCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="burnin_03", eac_id="EAC0008", narrative="Batch of temp files from an apparent nightly job, with a process still cleaning them up",
    capability_chain=["GenerateTemporalFilesCapability", "GenerateTemporalFilesCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="burnin_04", eac_id="EAC0008", narrative="An application log entry, a scratch temp file, and an environment variable left over from testing, consistent with ordinary uptime",
    capability_chain=["CreateLogFileCapability", "GenerateTemporalFilesCapability", "AddEnviromentVariableCapability"], compatible_roles=[]),
]

_PERIPHERAL_MANAGEMENT = [
  ScenarioTemplate(scenario_id="peripheral_01", eac_id="EAC0010", narrative="A phantom peripheral device (print server, KVM-over-IP), the connection it holds open, a log entry from when it was added, and the process managing it",
    capability_chain=["InjectFakeNetworkDeviceCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
]

_POCKET_LITTER = [
  ScenarioTemplate(scenario_id="pocketlitter_01", eac_id="EAC0011", narrative="Personal shell dotfiles, stray temp files, and a bash history suggesting a real, slightly messy user",
    capability_chain=["GenerateUserDotFilesCapability", "GenerateTemporalFilesCapability", "ModifyBashHistoryCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="pocketlitter_02", eac_id="EAC0011", narrative="Scratch files, a log, the process that produced them, and its open connection, like someone was debugging something",
    capability_chain=["GenerateTemporalFilesCapability", "CreateLogFileCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="pocketlitter_03", eac_id="EAC0011", narrative="A stray cloud credentials file, the dotfiles of whoever left it, an env var pointing at the account, and the account itself",
    capability_chain=["CreateFakeAWSCredentialsCapability", "GenerateUserDotFilesCapability", "AddEnviromentVariableCapability", "CreateFakeUserAccountCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="pocketlitter_04", eac_id="EAC0011", narrative="An ad-hoc file with lived-in timestamps and a log entry noting when it was touched",
    capability_chain=["CreateFileCapability", "ModifyFileMetadataCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="pocketlitter_05", eac_id="EAC0011", narrative="Dotfiles, stray temp files, a log, and the bash history tying them together, a fuller 'lived-in' picture",
    capability_chain=["GenerateUserDotFilesCapability", "GenerateTemporalFilesCapability", "CreateLogFileCapability", "ModifyBashHistoryCapability"], compatible_roles=[]),
]

_PERSONAS = [
  ScenarioTemplate(scenario_id="personas_01", eac_id="EAC0012", narrative="A believable developer's dotfiles (gitconfig, bash aliases), a project env var they set, and their shell history",
    capability_chain=["GenerateUserDotFilesCapability", "AddEnviromentVariableCapability", "ModifyBashHistoryCapability"], compatible_roles=["workstation", "ci_runner"]),
  ScenarioTemplate(scenario_id="personas_02", eac_id="EAC0012", narrative="A persona with their own (fake) cloud credentials, a process actively using them, and the connection it opens",
    capability_chain=["GenerateUserDotFilesCapability", "CreateFakeAWSCredentialsCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="personas_03", eac_id="EAC0012", narrative="Cloud credentials tied to a persona whose account also exists on the host, with a log entry from their last login",
    capability_chain=["CreateFakeAWSCredentialsCapability", "CreateFakeUserAccountCapability", "CreateLogFileCapability"], compatible_roles=[]),
]

_SOFTWARE_MANIPULATION = [
  ScenarioTemplate(scenario_id="softmanip_01", eac_id="EAC0014", narrative="A command's output is quietly altered, reinforced by a misleading environment variable and a log entry explaining it away",
    capability_chain=["ManipulateCommandOutputCapability", "AddEnviromentVariableCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="softmanip_02", eac_id="EAC0014", narrative="Weakened password policy paired with a fake process that would exploit it, the connection it opens, and a log entry noting the change",
    capability_chain=["WeakenPasswordPolicyCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="softmanip_03", eac_id="EAC0014", narrative="A rogue-looking process with a matching open connection and a log entry someone left when they noticed it",
    capability_chain=["InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="softmanip_04", eac_id="EAC0014", narrative="Manipulated tool output, a weakened policy, and the process taking advantage of it, compounding the false lead",
    capability_chain=["ManipulateCommandOutputCapability", "WeakenPasswordPolicyCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="softmanip_05", eac_id="EAC0014", narrative="A core service quietly marked as failed, a log entry noting the tampering, and a temp file left behind from the attempted fix",
    capability_chain=["SimulateServiceFailureCapability", "CreateLogFileCapability", "GenerateTemporalFilesCapability"], compatible_roles=[]),
]

_INFORMATION_MANIPULATION = [
  ScenarioTemplate(scenario_id="infomanip_01", eac_id="EAC0015", narrative="A misleading environment variable (e.g. a stale DEPLOY_ENV=staging on what looks like prod), backed by altered tool output, a log entry rationalizing it, and a weakened policy that reinforces the false context",
    capability_chain=["AddEnviromentVariableCapability", "ManipulateCommandOutputCapability", "CreateLogFileCapability", "WeakenPasswordPolicyCapability"], compatible_roles=[]),
]

_NETWORK_MANIPULATION = [
  ScenarioTemplate(scenario_id="netmanip_01", eac_id="EAC0016", narrative="An unexplained outbound connection over a phantom interface, a log entry noting the redirect, and the process routing it, as if traffic is being throttled",
    capability_chain=["InjectFakeNetworkConnectionCapability", "InjectFakeNetworkDeviceCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
]

_SECURITY_CONTROLS = [
  ScenarioTemplate(scenario_id="secctrl_01", eac_id="EAC0018", narrative="A visibly weakened password policy, prior sudo use, a log entry noting the change, and the account that benefited from it, the classic 'someone loosened this for convenience' story",
    capability_chain=["WeakenPasswordPolicyCapability", "SimulateSudoAbuseCapability", "CreateLogFileCapability", "CreateFakeUserAccountCapability"], compatible_roles=[]),
]

_BASELINE = [
  ScenarioTemplate(scenario_id="baseline_01", eac_id="EAC0019", narrative="Revert every injected decoy back to the session's starting state",
    capability_chain=["ResetToBaselineCapability"], compatible_roles=[]),
]

_APPLICATION_DIVERSITY = [
  ScenarioTemplate(scenario_id="appdiv_01", eac_id="EAC0006", narrative="An extra database service, the connection it holds open, a log entry from its setup, and the process it runs as, widening the apparent attack surface",
    capability_chain=["InjectFakeApplicationCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=["web_server", "workstation"]),
  ScenarioTemplate(scenario_id="appdiv_02", eac_id="EAC0006", narrative="A second, unrelated web-adjacent service listening alongside the primary one, with its own process visible",
    capability_chain=["InjectFakeApplicationCapability", "InjectFakeNetworkConnectionCapability", "InjectFakeProcessCapability"], compatible_roles=["database_server", "file_server", "mail_relay"]),
]

_NETWORK_DIVERSITY = [
  ScenarioTemplate(scenario_id="netdiv_01", eac_id="EAC0007", narrative="An extra network interface carrying an active connection, a log entry noting when it came up, and the process bound to it, implying a multi-homed environment",
    capability_chain=["InjectFakeNetworkDeviceCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
]

_MALWARE_DETONATION = [
  ScenarioTemplate(scenario_id="malware_01", eac_id="EAC0013", narrative="A dropped payload appears to have run, leaving a process, an open connection, a log entry, and a scratch file from its unpacking",
    capability_chain=["SimulateMalwareDetonationCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability", "GenerateTemporalFilesCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="malware_02", eac_id="EAC0013", narrative="Payload execution simulated right after an ingress tool transfer, with a temp file left behind and a log entry completing the story",
    capability_chain=["SimulateMalwareDetonationCapability", "GenerateTemporalFilesCapability", "CreateLogFileCapability"], compatible_roles=[]),
]

_INTRODUCED_VULNERABILITIES = [
  ScenarioTemplate(scenario_id="vuln_01", eac_id="EAC0023", narrative="An outdated, exploitable package planted for the attacker to find, with a log noting its install, a process depending on it, and its open connection",
    capability_chain=["IntroduceVulnerablePackageCapability", "CreateLogFileCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="vuln_02", eac_id="EAC0023", narrative="Outdated package paired with a weakened password policy and prior sudo use, three angles on the same target",
    capability_chain=["IntroduceVulnerablePackageCapability", "WeakenPasswordPolicyCapability", "SimulateSudoAbuseCapability"], compatible_roles=[]),
]

_API_MONITORING = [
  ScenarioTemplate(scenario_id="apimon_01", eac_id="EAC0001", narrative="Audit trail showing someone else was already probing this host, captured in the logs, with the monitoring process still running and its connection open",
    capability_chain=["SimulateFailedLoginAttemptsCapability", "CreateLogFileCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="apimon_02", eac_id="EAC0001", narrative="A monitored privilege escalation from a prior session, logged as if audit tooling caught it, with a temp file from the audit run",
    capability_chain=["SimulateSudoAbuseCapability", "CreateLogFileCapability", "GenerateTemporalFilesCapability"], compatible_roles=[]),
]

_NETWORK_MONITORING = [
  ScenarioTemplate(scenario_id="netmon_01", eac_id="EAC0002", narrative="A visible network-monitoring agent process (IDS-like), its capture connection, a log entry from its last alert, and a scratch file from its capture buffer, implying traffic is being watched",
    capability_chain=["InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability", "GenerateTemporalFilesCapability"], compatible_roles=[]),
]

_SYSTEM_ACTIVITY_MONITORING = [
  ScenarioTemplate(scenario_id="sysmon_01", eac_id="EAC0003", narrative="An audit/logging service that's visibly stopped working, a log capturing the moment it died, and a temp file left mid-write",
    capability_chain=["SimulateServiceFailureCapability", "CreateLogFileCapability", "GenerateTemporalFilesCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="sysmon_02", eac_id="EAC0003", narrative="A fresh system log entry, scratch files, the monitoring process producing them, and its capture connection, consistent with active auditing",
    capability_chain=["CreateLogFileCapability", "GenerateTemporalFilesCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
]

_NETWORK_ANALYSIS = [
  ScenarioTemplate(scenario_id="netanalysis_01", eac_id="EAC0004", narrative="A packet-capture-style process actively running, bound to its control socket, with a log entry from its last capture",
    capability_chain=["InjectFakeProcessCapability", "InjectFakeUnixSocketCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="netanalysis_02", eac_id="EAC0004", narrative="A control socket for a traffic-analysis tool, the connection it is monitoring, the process that owns the socket, and a log entry from its last capture",
    capability_chain=["InjectFakeUnixSocketCapability", "InjectFakeNetworkConnectionCapability", "InjectFakeProcessCapability", "CreateLogFileCapability"], compatible_roles=[]),
]

_EMAIL_MANIPULATION = [
  ScenarioTemplate(scenario_id="email_01", eac_id="EAC0009", narrative="A mail transport agent installed and listening on its SMTP connection, with a log entry from its last delivery and the process handling the queue, the closest honest observable to 'this host handles email'",
    capability_chain=["InjectFakeApplicationCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=["mail_relay"]),
]

_ISOLATION = [
  ScenarioTemplate(scenario_id="isolation_01", eac_id="EAC0020", narrative="Restrictive egress firewall rules, a log noting the segmentation, and a phantom monitoring process watching the boundary",
    capability_chain=["InjectRestrictiveFirewallRulesCapability", "CreateLogFileCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="isolation_02", eac_id="EAC0020", narrative="Segmentation firewall rules, a phantom monitoring agent, the connection it holds open, and a log entry from its last check, a watched-and-contained segment story",
    capability_chain=["InjectRestrictiveFirewallRulesCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability", "CreateLogFileCapability"], compatible_roles=[]),
]

_ATTACK_VECTOR_MIGRATION = [
  ScenarioTemplate(scenario_id="avmigration_01", eac_id="EAC0021", narrative="An endpoint agent quarantines a file the attacker just staged, leaves its process running, and logs the action, moving it out from under them",
    capability_chain=["SimulateFileQuarantineCapability", "InjectFakeProcessCapability", "CreateLogFileCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="avmigration_02", eac_id="EAC0021", narrative="A staged artifact is quarantined, a matching agent log entry appears, a temp file remains from the cleanup, and the agent process is still visible, completing the EDR story",
    capability_chain=["SimulateFileQuarantineCapability", "CreateLogFileCapability", "GenerateTemporalFilesCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
]

_ARTIFACT_DIVERSITY = [
  ScenarioTemplate(scenario_id="artifactdiversity_01", eac_id="EAC0022", narrative="Fake AWS credentials, the process that would use them, and the network connection it holds open",
    capability_chain=["CreateFakeAWSCredentialsCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="artifactdiversity_02", eac_id="EAC0022", narrative="A second local account, a temp file it left behind, and the process still running under it",
    capability_chain=["CreateFakeUserAccountCapability", "GenerateTemporalFilesCapability", "InjectFakeProcessCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="artifactdiversity_03", eac_id="EAC0022", narrative="Full spread: a fake account, matching AWS keys, the process using them, and the connection it opens",
    capability_chain=["CreateFakeUserAccountCapability", "CreateFakeAWSCredentialsCapability", "InjectFakeProcessCapability", "InjectFakeNetworkConnectionCapability"], compatible_roles=[]),
  ScenarioTemplate(scenario_id="artifactdiversity_04", eac_id="EAC0022", narrative="An open network connection, the process holding it, and a stray temp file from whatever it was doing",
    capability_chain=["InjectFakeNetworkConnectionCapability", "InjectFakeProcessCapability", "GenerateTemporalFilesCapability"], compatible_roles=[]),
]

SCENARIO_CATALOG: list[ScenarioTemplate] = (
  _LURES + _BURN_IN + _PERIPHERAL_MANAGEMENT + _POCKET_LITTER + _PERSONAS
  + _SOFTWARE_MANIPULATION + _INFORMATION_MANIPULATION + _NETWORK_MANIPULATION
  + _SECURITY_CONTROLS + _BASELINE + _APPLICATION_DIVERSITY + _NETWORK_DIVERSITY
  + _MALWARE_DETONATION + _INTRODUCED_VULNERABILITIES
  + _API_MONITORING + _NETWORK_MONITORING + _SYSTEM_ACTIVITY_MONITORING
  + _NETWORK_ANALYSIS + _EMAIL_MANIPULATION
  + _ISOLATION + _ATTACK_VECTOR_MIGRATION + _ARTIFACT_DIVERSITY
)


def scenarios_for_activity(eac_id: str, role_id: str | None = None) -> list[ScenarioTemplate]:
  candidates = [s for s in SCENARIO_CATALOG if s.eac_id == eac_id]
  if role_id is None:
    return candidates
  return [s for s in candidates if s.fits_role(role_id)]
