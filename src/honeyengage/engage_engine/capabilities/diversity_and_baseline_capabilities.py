"""Capabilities that add application or network diversity and reset the host to its baseline."""

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import ProcessData, VirtualShell


class InjectFakeApplicationCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "package_name": "Name of a plausible additional application/service package (e.g. mysql-server, redis-server).",
      "package_version": "A plausible version string for that package (e.g. 8.0.36-0ubuntu0.22.04.1).",
      "package_description": "A short one-line description of the package.",
      "process_command": "The command line of the process this application would run as (e.g. /usr/sbin/mysqld).",
      "process_pid": "A plausible process ID (integer) for this application, not already in use.",
    }

  def execute(self) -> CapabilityResult:
    package_name = getattr(self.options, "package_name", None)
    process_command = getattr(self.options, "process_command", None)
    if not package_name or not process_command:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="package_name and process_command are required to inject a fake application."
      )

    self.virtual_shell.inject_fake_package({
      "name": package_name,
      "version": getattr(self.options, "package_version", None) or "1.0.0-1",
      "description": getattr(self.options, "package_description", None) or f"{package_name} service",
    })

    pid = getattr(self.options, "process_pid", None)
    if not isinstance(pid, int):
      pid = 2000

    self.virtual_shell.inject_fake_process(ProcessData(
      user=self.virtual_shell.current_user,
      pid=pid,
      cpu_usage=0.2,
      memory_usage=1.5,
      vsz=45000,
      rss=12000,
      tty="?",
      stat="Sl",
      start_time="Jul16",
      time="0:03",
      command=process_command,
    ))

    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"Injected fake application '{package_name}' with matching process '{process_command}'."
    )


class InjectFakeNetworkDeviceCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "interface_name": "Plausible network interface name (e.g. eth1, docker0, br-a1b2c3d4e5f6).",
      "mac_address": "A plausible MAC address for the interface (format xx:xx:xx:xx:xx:xx).",
      "ipv4_address": "A plausible IPv4 address with CIDR for the interface (e.g. 172.17.0.1/16).",
    }

  def execute(self) -> CapabilityResult:
    interface_name = getattr(self.options, "interface_name", None)
    ipv4_address = getattr(self.options, "ipv4_address", None)
    if not interface_name or not ipv4_address:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="interface_name and ipv4_address are required to inject a fake network device."
      )

    mac_address = getattr(self.options, "mac_address", None) or "02:42:ac:11:00:01"

    self.virtual_shell.inject_fake_network_interface({
      "name": interface_name,
      "mac_address": mac_address,
      "ipv4_address": ipv4_address,
      "state": "UP",
    })

    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"Injected fake network interface '{interface_name}' ({ipv4_address})."
    )


class SimulateMalwareDetonationCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "process_command": "The command line the 'detonated' payload would appear to run as (e.g. /tmp/update.sh).",
      "process_pid": "A plausible process ID (integer) for the detonated payload.",
      "log_line": "A single plausible syslog/auth log line reflecting the payload having executed (no honeypot-revealing wording).",
    }

  def execute(self) -> CapabilityResult:
    process_command = getattr(self.options, "process_command", None)
    if not process_command:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="process_command is required to simulate malware detonation."
      )

    pid = getattr(self.options, "process_pid", None)
    if not isinstance(pid, int):
      pid = 3000

    self.virtual_shell.inject_fake_process(ProcessData(
      user=self.virtual_shell.current_user,
      pid=pid,
      cpu_usage=12.4,
      memory_usage=2.1,
      vsz=8192,
      rss=2048,
      tty="?",
      stat="R",
      start_time="now",
      time="0:01",
      command=process_command,
    ))

    log_line = getattr(self.options, "log_line", None)
    if log_line:
      log_path = "/var/log/syslog"
      if not self.vfs.exists(log_path):
        self.vfs.mkfile_p(log_path, uid=0, gid=4, size=0, mode="rw-r-----")
      existing = self.vfs.file_contents(log_path)
      self.vfs.override_file_contents(log_path, existing + f"{log_line}\n".encode())

    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"Simulated detonation of '{process_command}' (pid {pid})."
    )


class IntroduceVulnerablePackageCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "package_name": "Name of a real-world package plausibly present on a Linux server (e.g. openssl, sudo, log4j).",
      "vulnerable_version": "An outdated version string for that package, plausibly vulnerable (e.g. 1.1.1f-1ubuntu2.16).",
      "package_description": "A short one-line description of the package.",
    }

  def execute(self) -> CapabilityResult:
    package_name = getattr(self.options, "package_name", None)
    vulnerable_version = getattr(self.options, "vulnerable_version", None)
    if not package_name or not vulnerable_version:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="package_name and vulnerable_version are required to introduce a vulnerable package."
      )

    self.virtual_shell.inject_fake_package({
      "name": package_name,
      "version": vulnerable_version,
      "description": getattr(self.options, "package_description", None) or f"{package_name} package",
    })

    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"Introduced vulnerable package '{package_name}' version {vulnerable_version}."
    )


class ResetToBaselineCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {}

  def execute(self) -> CapabilityResult:
    removed = self.virtual_shell.reset_to_baseline()
    total_removed = sum(removed.values())
    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"Reset to baseline: removed {total_removed} injected artifact(s) ({removed})."
    )
