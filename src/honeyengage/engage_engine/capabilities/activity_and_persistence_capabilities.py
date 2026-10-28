"""Capabilities that plant scheduled jobs, services, and other signs of activity and persistence."""

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


class SimulateFailedLoginAttemptsCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "attempts": (
        "List of dictionaries, each with: username (string), source_ip (string), "
        "success (boolean), timestamp_label (string, e.g. 'Jul 14 03:22:10'), "
        "method (string, e.g. 'password' or 'publickey'). Provide 2-5 entries."
      ),
    }

  def execute(self) -> CapabilityResult:
    attempts = getattr(self.options, "attempts", None)
    if not attempts or not isinstance(attempts, list):
      return CapabilityResult(success=False, eac_id=self.eac_id, message="attempts is required to simulate failed login history.")

    injected = 0
    for attempt in attempts:
      if not isinstance(attempt, dict):
        continue
      required = {"username", "source_ip", "success", "timestamp_label"}
      if not required.issubset(attempt.keys()):
        continue
      self.virtual_shell.inject_login_event(attempt)
      injected += 1

    if injected == 0:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="No valid login attempts in the provided data.")

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Injected {injected} login event(s) into session history.")


class SimulateServiceFailureCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "unit_name": "The systemd unit name to mark as failed (e.g. cron.service). Prefer an existing/plausible unit for this machine's role.",
    }

  def execute(self) -> CapabilityResult:
    unit_name = getattr(self.options, "unit_name", None)
    if not unit_name:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="unit_name is required to simulate a service failure.")

    existing = next((u for u in self.virtual_shell.systemd_units if u.name == unit_name), None)
    if existing is not None:
      existing.active_state = "failed"
      existing.sub_state = "failed"
    else:
      self.virtual_shell.inject_fake_systemd_unit({
        "name": unit_name, "load_state": "loaded", "active_state": "failed", "sub_state": "failed",
        "description": getattr(self.options, "description", "") or unit_name,
      })

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Marked {unit_name} as failed.")


class InjectFakeUnixSocketCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "socket_path": "Plausible Unix socket path (e.g. /var/run/docker.sock, /run/mysqld/mysqld.sock).",
      "process_command": "The process command that would own this socket (e.g. /usr/bin/dockerd).",
    }

  def execute(self) -> CapabilityResult:
    socket_path = getattr(self.options, "socket_path", None)
    process_command = getattr(self.options, "process_command", None)
    if not socket_path or not process_command:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="socket_path and process_command are required.")

    self.virtual_shell.inject_fake_unix_socket({"path": socket_path, "process_command": process_command})
    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Injected fake Unix socket at {socket_path}.")


class SimulateSudoAbuseCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "sudo_command": "A plausible prior sudo command (e.g. 'sudo systemctl restart mysql').",
      "username": "The username that appeared to run it (e.g. 'daniel').",
    }

  def execute(self) -> CapabilityResult:
    sudo_command = getattr(self.options, "sudo_command", None)
    username = getattr(self.options, "username", None)
    if not sudo_command or not username:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="sudo_command and username are required.")

    existing_history = str(self.vfs.file_contents("/root/.bash_history") or "") if self.vfs.exists("/root/.bash_history") else ""
    new_history = existing_history + f"{sudo_command}\n"
    if not self.vfs.exists("/root/.bash_history"):
      self.vfs.mkfile_p("/root/.bash_history", uid=0, gid=0, size=len(new_history), mode="-rw-------")
    self.vfs.override_file_contents("/root/.bash_history", new_history.encode('utf-8'))

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Recorded prior sudo usage by '{username}'.")


class PlantSshAuthorizedKeyCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "user": "Username whose authorized_keys file should get the extra entry (e.g. 'root' or 'daniel').",
      "key_comment": "The trailing comment on the fake public key line (e.g. 'deploy@ci-runner-03').",
    }

  def execute(self) -> CapabilityResult:
    user = getattr(self.options, "user", None)
    key_comment = getattr(self.options, "key_comment", None)
    if not user or not key_comment:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="user and key_comment are required.")

    home = "/root" if user == "root" else f"/home/{user}"
    path = f"{home}/.ssh/authorized_keys"
    fake_key_body = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7" + ("x" * 300)
    line = f"ssh-rsa {fake_key_body} {key_comment}\n"

    existing = str(self.vfs.file_contents(path) or "") if self.vfs.exists(path) else ""
    new_content = existing + line
    if not self.vfs.exists(path):
      self.vfs.mkfile_p(path, uid=0, gid=0, size=len(new_content), mode="-rw-------")
    self.vfs.override_file_contents(path, new_content.encode('utf-8'))

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Planted authorized_keys entry for '{user}'.")


class SimulateFirewallActivityCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "rule_target": "The rule's target (e.g. '3306/tcp' or '10.0.0.0/8').",
      "action": "One of: allow, deny, reject.",
    }

  def execute(self) -> CapabilityResult:
    rule_target = getattr(self.options, "rule_target", None)
    action = getattr(self.options, "action", None)
    if not rule_target or action not in ("allow", "deny", "reject"):
      return CapabilityResult(success=False, eac_id=self.eac_id, message="rule_target and a valid action (allow/deny/reject) are required.")

    verb = {"allow": "ALLOW", "deny": "DENY", "reject": "REJECT"}[action]
    self.virtual_shell.firewall_rules.append(f"{rule_target:<27}{verb:<12}Anywhere")

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Added firewall rule: {action} {rule_target}.")
