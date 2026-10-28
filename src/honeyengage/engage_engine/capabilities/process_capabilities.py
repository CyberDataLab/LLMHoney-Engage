"""Capabilities that plant processes in the process table."""

from src.honeyengage.engage_engine.capabilities.utils import Capability, CapabilityResult
from src.honeyengage.virtual_env.vfs import VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import ProcessData, VirtualShell


class InjectFakeProcessCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "process_data": "Dictionary with the following fields: \n"
      "- pid: Process ID (integer)\n"
      "- cpu_usage: CPU usage percentage (float)\n"
      "- memory_usage: Memory usage percentage (float)\n"
      "- vsz: Virtual memory size (integer)\n"
      "- rss: Resident set size (integer)\n"
      "- stat: Process state (string)\n"
      "- start_time: Start time of the process (string)\n"
      "- time: CPU time consumed by the process (string)\n"
      "- command: Command executed by the process (string)",
    }
  
  def execute(self) -> CapabilityResult:
    options = getattr(self.options, "process_data", None)
    if not options:
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="Process data is required to inject a fake process."
      )
    if isinstance(options, list):
      options = next((item for item in options if isinstance(item, dict)), None)
    if not isinstance(options, dict):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message="Process data must be a dictionary (or a list containing one)."
      )
    pid, cpu_usage, memory_usage, vsz, rss, stat, start_time, time, command = (
      options.get("pid", 0),
      options.get("cpu_usage", 0.0),
      options.get("memory_usage", 0.0),
      options.get("vsz", 0),
      options.get("rss", 0),
      options.get("stat", ""),
      options.get("start_time", ""),
      options.get("time", ""),
      options.get("command", "")
    )
    if (not isinstance(pid, int) or 
        not isinstance(cpu_usage, (int, float)) or 
        not isinstance(memory_usage, (int, float)) or 
        not isinstance(vsz, int) or 
        not isinstance(rss, int) or 
        not isinstance(stat, str) or 
        not isinstance(start_time, str) or 
        not isinstance(time, str) or 
        not isinstance(command, str)
    ):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id,
        message="Invalid data types in process_data. Expected types: pid (int), cpu_usage (float), memory_usage (float), vsz (int), rss (int), stat (str), start_time (str), time (str), command (str)."
      )
    process_data = ProcessData(
      user=self.virtual_shell.current_user,
      pid=options.get("pid", 0),
      cpu_usage=options.get("cpu_usage", 0.0),
      memory_usage=options.get("memory_usage", 0.0),
      vsz=options.get("vsz", 0),
      rss=options.get("rss", 0),
      tty=self.virtual_shell.current_tty,
      stat=options.get("stat", ""),
      start_time=options.get("start_time", ""),
      time=options.get("time", ""),
      command=options.get("command", "")
    )
    self.virtual_shell.inject_fake_process(process_data)
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message="Discovery output spoofed successfully."
    )