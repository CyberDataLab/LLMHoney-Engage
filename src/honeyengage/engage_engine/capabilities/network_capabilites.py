"""Capabilities that plant network interfaces and connections."""

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


class InjectFakeNetworkConnectionCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "network_data": "Dictionary with the following fields: \n"
      "- protocol: Network protocol (string)\n"
      "- local_address: Local IP address and port (string)\n"
      "- remote_address: Remote IP address and port (string)\n"
      "- state: Connection state (string)",
    }
  
  def execute(self) -> CapabilityResult:
    network_data = getattr(self.options, "network_data", None)
    if not network_data:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="Network data is required to inject a fake network connection."
      )
    if isinstance(network_data, list):
      network_data = next((item for item in network_data if isinstance(item, dict)), None)
    if not isinstance(network_data, dict):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="Network data must be a dictionary (or a list containing one)."
      )
    self.virtual_shell.inject_fake_network_connection(network_data)
    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message="Discovery output spoofed successfully."
    )


class InjectRestrictiveFirewallRulesCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "blocked_targets": (
        "List of 2-4 targets a segmented host would block outbound (e.g. "
        "'10.0.0.0/8', '192.168.0.0/16', '169.254.169.254', '0.0.0.0/0 out'). "
        "Prefer internal ranges and metadata endpoints, not this host's own "
        "listening ports."
      ),
    }

  def execute(self) -> CapabilityResult:
    blocked_targets = getattr(self.options, "blocked_targets", None)
    if not blocked_targets or not isinstance(blocked_targets, list):
      return CapabilityResult(success=False, eac_id=self.eac_id, message="blocked_targets (a list) is required to tighten the firewall.")

    existing = set(self.virtual_shell.firewall_rules)
    added = 0
    for target in blocked_targets:
      if not isinstance(target, str) or not target.strip():
        continue
      rule = f"{target.strip():<27}{'DENY':<12}Anywhere"
      if rule in existing:
        continue
      self.virtual_shell.firewall_rules.append(rule)
      existing.add(rule)
      added += 1

    if added == 0:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="No valid new deny targets in the provided data.")

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Added {added} restrictive firewall rule(s) simulating a segmented network.")