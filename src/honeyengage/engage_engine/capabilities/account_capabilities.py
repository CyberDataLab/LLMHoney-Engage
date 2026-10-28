"""Capabilities that plant user accounts and their traces."""

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


class CreateFakeUserAccountCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "username": "Username for the fake account to create.",
    }
  
  def execute(self) -> CapabilityResult:
    account_name = getattr(self.options, "username", None)
    if not account_name:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Username is required to create a fake user account."
      )
    try:
      current_passwd = self.vfs.file_contents("/etc/passwd").decode('utf-8')
      current_shadow = self.vfs.file_contents("/etc/shadow").decode('utf-8')
    except Exception:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to create fake account '{account_name}'."
      )
        
    new_passwd = current_passwd + f"{account_name}:x:1001:1001:{account_name}:/home/devops:/bin/bash\n"
    new_shadow = current_shadow + f"{account_name}:$1$salt$Gcm6FsVtF/Qa7.ZZsR.X.0:18600:0:99999:7:::\n"
    
    self.vfs.override_file_contents("/etc/passwd", new_passwd.encode('utf-8'))
    self.vfs.override_file_contents("/etc/shadow", new_shadow.encode('utf-8'))
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Fake account '{account_name}' created successfully."
    )

class GenerateUserDotFilesCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "username": "Username for the fake account to create dotfiles for.",
      "filename": "Name of the dotfile to generate (for example: .bashrc, .gitconfig...).",
      "file_content": "Content of the dotfile to generate."
    }
  
  def execute(self) -> CapabilityResult:
    account_name = getattr(self.options, "username", None)
    filename = getattr(self.options, "filename", None)
    file_content = getattr(self.options, "file_content", None)
    if not account_name or not filename or not file_content:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="All options (username, filename, file_content) are required to generate a dotfile."
      )
    
    home_dir = f"/home/{account_name}"
    file_path = filename
    if not file_path.startswith("/home/"):
      file_path = f"{home_dir}/{filename}"

    if not self.vfs.exists(file_path):
      self.vfs.mkfile_p(file_path, uid=1001, gid=1001, size=1024, mode="rw-r--r--")
    
    if not self.vfs.override_file_contents(file_path, file_content.encode('utf-8')):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message=f"Failed to generate dotfile {file_path} for user '{account_name}'."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Dotfiles for user '{account_name}' generated successfully."
    )