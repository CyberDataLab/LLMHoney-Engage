"""Capabilities that plant files and logs."""

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


class CreateFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file to create.",
      "file_content": "Initial content that should be written to the file.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to create a file."
      )
    file_content = getattr(self.options, "file_content", None)
    if not file_content:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File content is required to create a file."
      )
    if isinstance(file_content, str):
      file_content = file_content.encode('utf-8')

    if self.vfs.exists(file_path):
      original_path = file_path
      suffix = 1
      while self.vfs.exists(file_path) and suffix < 100:
        file_path = f"{original_path}.{suffix}"
        suffix += 1
      if self.vfs.exists(file_path):
        return CapabilityResult(
          success=False,
          eac_id=self.eac_id,
          message=f"File {original_path} and its numbered variants already exist. Cannot create file."
        )

    self.vfs.mkfile_p(file_path, uid=0, gid=0, size=len(file_content), mode="rw-r--r--")
    
    if not self.vfs.override_file_contents(file_path, file_content):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message=f"Failed to create file {file_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} created successfully with provided content."
    )

class DeleteFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file to delete.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to delete a file."
      )
    
    if not self.vfs.exists(file_path):
      self.vfs.mkfile_p(file_path, uid=0, gid=0, size=0, mode="rw-r--r--")

    if not self.vfs.delete_node(file_path):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message=f"Failed to delete file {file_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} deleted successfully."
    )

class ModifyFileContentCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file whose content should be modified.",
      "new_content": "Replacement content for the file.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to modify file content."
      )
    new_content = getattr(self.options, "new_content", None)
    if new_content is None:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="New content is required to modify file content."
      )
    if isinstance(new_content, str):
      new_content = new_content.encode('utf-8')

    if not self.vfs.exists(file_path):
      self.vfs.mkfile_p(file_path, uid=0, gid=0, size=0, mode="rw-r--r--")

    if not self.vfs.override_file_contents(file_path, new_content):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to modify content for file {file_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} content modified successfully."
    )

class ModifyFileMetadataCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file whose metadata should be modified.",
      "new_metadata": "Dictionary of metadata values to apply, such as mode, uid, and gid.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to modify file metadata."
      )
    new_metadata = getattr(self.options, "new_metadata", None)
    if not new_metadata:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="New metadata is required to modify file metadata."
      )
    
    if not self.vfs.exists(file_path):
      self.vfs.mkfile_p(file_path, uid=0, gid=0, size=0, mode="rw-r--r--")

    if not self.vfs.override_file_metadata(file_path, new_metadata):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to modify metadata for file {file_path}."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} metadata modified successfully."
    )

class ModifyBashHistoryCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "commands": "Array of commands to add to the bash history.",
      "replace": "Boolean indicating whether to replace the entire history or append to it.",
    }
  
  def execute(self) -> CapabilityResult:
    commands = getattr(self.options, "commands", None)
    if not commands:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Commands are required to modify bash history."
      )

    replace = getattr(self.options, "replace", False)
    if isinstance(replace, str):
      replace = replace.lower() == "true"
    if not isinstance(replace, bool):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="Replace option must be a boolean value."
      )

    bash_history_path = f"{self.virtual_shell._home_dir_for(self.current_user)}/.bash_history"
    if self.vfs.get_node(bash_history_path) is None:
      self.vfs.mkfile_p(bash_history_path, uid=0, gid=0, size=0, mode="rw-------")
    if replace:
      new_history = "\n".join(commands) + "\n"
    else:
      existing_history = str(self.vfs.file_contents(bash_history_path) or "")
      new_history = existing_history + "\n".join(commands) + "\n"
    if not self.vfs.override_file_contents(bash_history_path, new_history.encode('utf-8')):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="Failed to modify bash history."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message="Bash history modified successfully."
    )

class ModifyHostsFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "ip": "IP address to add to the host.",
      "hostname": "Hostname to associate with the IP address.",
    }
  
  def execute(self) -> CapabilityResult:
    ip = getattr(self.options, "ip", None)
    hostname = getattr(self.options, "hostname", None)
    if not ip or not hostname:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="IP address and hostname are required to modify /etc/hosts."
      )
    
    existing_hosts_content = str(self.vfs.file_contents("/etc/hosts") or "")
    new_hosts_content = existing_hosts_content + f"{ip} {hostname}\n"

    hosts_file_path = "/etc/hosts"
    if not self.vfs.override_file_contents(hosts_file_path, new_hosts_content.encode('utf-8')):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Failed to modify /etc/hosts."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message="/etc/hosts modified successfully."
    )

class CreateLogFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "log_path": "Path of the log file to create, must begin with '/var/log/'.",
      "log_content": "Content that should be written to the log file.",
    }
  
  def execute(self) -> CapabilityResult:
    log_path = getattr(self.options, "log_path", None)
    if not log_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Log path is required to create a log file."
      )
    log_content = getattr(self.options, "log_content", None)
    if not log_content:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Log content is required to create a log file."
      )
    if isinstance(log_content, str):
      log_content = log_content.encode('utf-8')

    if self.vfs.exists(log_path):
      rotated_path = log_path
      for suffix in range(1, 10):
        candidate = f"{log_path}.{suffix}"
        if not self.vfs.exists(candidate):
          rotated_path = candidate
          break
      if rotated_path != log_path:
        self.vfs.mkfile_p(rotated_path, uid=0, gid=0, size=len(log_content), mode="rw-r--r--")
        if not self.vfs.override_file_contents(rotated_path, log_content):
          return CapabilityResult(
            success=False,
            eac_id=self.eac_id,
            message=f"Failed to create rotated log file {rotated_path}."
          )
        return CapabilityResult(
          success=True,
          eac_id=self.eac_id,
          message=f"Log file {rotated_path} created successfully with provided content."
        )
      existing_content = self.vfs.file_contents(log_path) or b""
      if isinstance(existing_content, str):
        existing_content = existing_content.encode('latin-1')
      new_content = existing_content + log_content
      if not self.vfs.override_file_contents(log_path, new_content):
        return CapabilityResult(
          success=False,
          eac_id=self.eac_id,
          message=f"Failed to append to log file {log_path}."
        )
      self.vfs.override_file_metadata(log_path, {"size": len(new_content)})
      return CapabilityResult(
        success=True,
        eac_id=self.eac_id,
        message=f"Log file {log_path} appended successfully with provided content."
      )

    self.vfs.mkfile_p(log_path, uid=0, gid=0, size=len(log_content), mode="rw-r--r--")

    if not self.vfs.override_file_contents(log_path, log_content):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message=f"Failed to create log file {log_path}."
      )

    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"Log file {log_path} created successfully with provided content."
    )

class GenerateTemporalFilesCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "files": "Array containing a list of paths for the temporal files, should be located in /tmp, /var/tmp, /var/cache or similar directories.",
    }
  
  def execute(self) -> CapabilityResult:
    files = getattr(self.options, "files", None)
    if not files:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="List of files is required to generate temporal files."
      )

    for i, file_entry in enumerate(files):
      if isinstance(file_entry, dict):
        temp_file_path = file_entry.get("path") or f"/tmp/temp_file_{i}.txt"
        size = file_entry.get("size", 1024)
      else:
        temp_file_path = str(file_entry) if file_entry else f"/tmp/temp_file_{i}.txt"
        size = 1024
      try:
        size = int(size)
      except (TypeError, ValueError):
        size = 1024
      self.vfs.mkfile_p(temp_file_path, uid=0, gid=0, size=size, mode="rw-r--r--")

    return CapabilityResult(
      success=True,
      eac_id=self.eac_id,
      message=f"{len(files)} temporal files generated successfully."
    )


class SimulateFileQuarantineCapability(Capability):

  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "target_path": "Absolute path of an artifact the attacker just staged that should be quarantined (e.g. '/tmp/payload.sh', '/dev/shm/x').",
      "agent_name": "Plausible endpoint-agent name performing the quarantine (e.g. 'falcon-sensor', 'wazuh', 'clamav').",
    }

  def execute(self) -> CapabilityResult:
    target_path = getattr(self.options, "target_path", None)
    agent_name = getattr(self.options, "agent_name", None)
    if not target_path or not agent_name:
      return CapabilityResult(success=False, eac_id=self.eac_id, message="target_path and agent_name are required to quarantine a file.")

    if not self.vfs.exists(target_path):
      return CapabilityResult(success=False, eac_id=self.eac_id, message=f"{target_path} does not exist; nothing to quarantine.")

    original_name = target_path.rstrip("/").split("/")[-1] or "artifact"

    try:
      original_bytes = self.vfs.file_contents(target_path)
    except Exception:
      original_bytes = b""

    if not self.vfs.delete_node(target_path):
      return CapabilityResult(success=False, eac_id=self.eac_id, message=f"Failed to remove {target_path} for quarantine.")

    quarantine_dir = f"/var/lib/{agent_name}/quarantine"
    quarantine_path = f"{quarantine_dir}/{original_name}.quarantine"
    self.vfs.mkfile_p(quarantine_path, uid=0, gid=0, size=len(original_bytes), mode="-rw-------")
    if original_bytes:
      self.vfs.override_file_contents(quarantine_path, original_bytes)

    return CapabilityResult(success=True, eac_id=self.eac_id, message=f"Quarantined {target_path} -> {quarantine_path} ({agent_name}).")