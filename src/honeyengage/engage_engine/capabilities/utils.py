"""Shared helpers of the deception capabilities."""

from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


class CapabilityResult:
  def __init__(self, success: bool, eac_id: str, message: str = ""):
    self.success = success
    self.eac_id = eac_id
    self.message = message

class Capability:
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.eac_id = eac_id
    self.current_user = virtual_shell.current_user
    self.current_tty = virtual_shell.current_tty
    self.options = options

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {}
  
  def execute(self) -> CapabilityResult:
    return CapabilityResult(
      success=False, 
      eac_id=self.eac_id, 
      message="Base capability does not implement execute method.")

