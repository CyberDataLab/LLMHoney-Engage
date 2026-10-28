"""Emulated Ubuntu shell: file system, processes, network state, services, and packages, answering commands without any language model."""

import base64
import bz2
import contextlib
import getopt
import gzip as gzip_module
import hashlib
import importlib
import io
import os
import pkgutil
import posixpath
import re
import secrets
import shlex
import socket
import sys
import zipfile
from collections.abc import Callable
from datetime import datetime, timedelta
from random import randint
from unittest.mock import MagicMock

from loguru import logger
from pydantic import BaseModel, Field

from src.honeyengage.virtual_env.cowrie.shell.command import MockProtocol
from src.honeyengage.virtual_env.machine_persona import MachineRole, pick_machine_role
from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, FSNode, VirtualFileSystem

sys.modules['treq'] = MagicMock()
sys.modules['twisted'] = MagicMock()
sys.modules['twisted.internet'] = MagicMock()
sys.modules['twisted.internet.defer'] = MagicMock()
sys.modules['twisted.internet.endpoints'] = MagicMock()
sys.modules['twisted.internet.protocol'] = MagicMock()
sys.modules['twisted.python'] = MagicMock()
sys.modules['twisted.web'] = MagicMock()
sys.modules['twisted.conch'] = MagicMock()

sys.modules['cowrie.core.artifact'] = MagicMock()
sys.modules['cowrie.core.network'] = MagicMock()
sys.modules['cowrie.shell.honeypot'] = MagicMock()

mock_pwd = MagicMock()
class FakePasswd:
    def __init__(self, *args, **kwargs): pass
    def getpwnam(self, name): return ["root", "x", 0, 0, "root", "/root", "/bin/bash"]
    def getpwuid(self, uid): return ["root", "x", 0, 0, "root", "/root", "/bin/bash"]
mock_pwd.Passwd = FakePasswd
sys.modules['cowrie.shell.pwd'] = mock_pwd

logger.add("logs/virtual_shell.log", rotation="10 MB")

class ProcessData(BaseModel):
  user: str = Field(..., description="The user who owns the process")
  pid: int = Field(..., description="The process ID")
  cpu_usage: float = Field(..., description="The CPU usage of the process")
  memory_usage: float = Field(..., description="The memory usage of the process")
  vsz: int = Field(..., description="The virtual memory size of the process")
  rss: int = Field(..., description="The resident set size of the process")
  tty: str = Field(..., description="The terminal associated with the process")
  stat: str = Field(..., description="The process state")
  start_time: str = Field(..., description="The start time of the process")
  time: str = Field(..., description="The cumulative CPU time of the process")
  command: str = Field(..., description="The command that started the process")

class NetworkConnection(BaseModel):
  protocol: str = Field(..., description="The protocol of the network connection (e.g., TCP, UDP)")
  local_address: str = Field(..., description="The local address and port (e.g., 127.0.0.1:8080)")
  remote_address: str = Field(..., description="The remote address and port (e.g., 192.168.1.1:443)")
  state: str = Field(..., description="The state of the network connection (e.g., ESTABLISHED, LISTEN)")

class InstalledPackage(BaseModel):
  name: str = Field(..., description="The package name (e.g., openssh-server)")
  version: str = Field(..., description="The package version string (e.g., 1.2.3-1ubuntu1)")
  architecture: str = Field(default="amd64", description="The package architecture")
  description: str = Field(default="", description="A short package description")

class NetworkInterface(BaseModel):
  name: str = Field(..., description="The interface name (e.g., eth1, docker0)")
  mac_address: str = Field(..., description="The interface's MAC address")
  ipv4_address: str = Field(..., description="The interface's IPv4 address with CIDR (e.g., 172.17.0.1/16)")
  state: str = Field(default="UP", description="The interface state (UP or DOWN)")

class SystemdUnit(BaseModel):
  name: str = Field(..., description="The unit name (e.g., cron.service)")
  load_state: str = Field(default="loaded", description="systemd load state (loaded, not-found, ...)")
  active_state: str = Field(default="active", description="systemd active state (active, failed, inactive, ...)")
  sub_state: str = Field(default="running", description="systemd sub-state (running, dead, exited, ...)")
  description: str = Field(default="", description="Human-readable unit description")

class LoginEvent(BaseModel):
  username: str = Field(..., description="The username involved in the login event")
  source_ip: str = Field(..., description="The apparent source IP of the login attempt")
  success: bool = Field(..., description="Whether the login attempt succeeded")
  timestamp_label: str = Field(..., description="A plausible timestamp label as it would appear in a log (e.g. 'Jul 16 09:14:02')")
  method: str = Field(default="password", description="Auth method (password, publickey, ...)")

class UnixSocket(BaseModel):
  path: str = Field(..., description="The socket's filesystem path (e.g. /var/run/docker.sock)")
  process_command: str = Field(..., description="The process command that would own this socket")


class ShellTerminationError(RuntimeError):
  def __init__(self, output: str, exit_reason: str):
    super().__init__(exit_reason)
    self.output = output
    self.exit_reason = exit_reason

class VirtualShell:
  def __init__(self, vfs: VirtualFileSystem, user: str = "root", session_id: str | None = None, persona_role_id: str | None = None):
    self.vfs = vfs
    self.current_user = user
    self.current_tty = "tty1"

    self.persona: MachineRole = pick_machine_role(session_id or f"unseeded-{id(self)}", persona_role_id)

    self.process_list: list[ProcessData] = []
    self.network_connections: list[NetworkConnection] = []
    self.process_list.append(ProcessData(
       user="user",
       pid=974,
       cpu_usage=0.0,
       memory_usage=0.2,
       vsz=8744,
       rss=5488,
       tty="tty1",
       stat="S",
       start_time="15:17",
       time="0:00",
       command="bash"
    ))
    self.process_list.append(ProcessData(
       user="root",
       pid=1,
       cpu_usage=0.0,
       memory_usage=0.5,
       vsz=166256,
       rss=11704,
       tty="?",
       stat="Ss",
       start_time="15:12",
       time="0:01",
       command="/sbin/init"
    ))

    self.network_connections.append(NetworkConnection(
      protocol="TCP",
      local_address="127.0.0.1:8080",
      remote_address="192.168.1.1:443",
      state="ESTABLISHED"
    ))
    for port, _service_name in self.persona.typical_ports:
      self.network_connections.append(NetworkConnection(
        protocol="TCP",
        local_address=f"0.0.0.0:{port}",
        remote_address="0.0.0.0:*",
        state="LISTEN",
      ))

    self.installed_packages: list[InstalledPackage] = [
      InstalledPackage(name="openssh-server", version="1:8.9p1-3ubuntu0.6", description="secure shell (SSH) server"),
      InstalledPackage(name="curl", version="7.81.0-1ubuntu1.15", description="command line tool for transferring data"),
      InstalledPackage(name="python3", version="3.10.6-1~22.04", description="interactive high-level object-oriented language"),
      InstalledPackage(name="sudo", version="1.9.9-1ubuntu2.4", description="provide limited super user privileges"),
      InstalledPackage(name="systemd", version="249.11-0ubuntu3.12", description="system and service manager"),
      InstalledPackage(name="cron", version="3.0pl1-137ubuntu3", description="process scheduling daemon"),
    ]
    for package_name, version, description in self.persona.typical_packages:
      self.installed_packages.append(InstalledPackage(name=package_name, version=version, description=description))

    self.extra_network_interfaces: list[NetworkInterface] = []

    self.systemd_units: list[SystemdUnit] = [
      SystemdUnit(name="ssh.service", description="OpenBSD Secure Shell server"),
      SystemdUnit(name="cron.service", description="Regular background program processing daemon"),
    ]
    for _port, service_name in self.persona.typical_ports:
      self.systemd_units.append(SystemdUnit(name=f"{service_name}.service", description=f"{service_name} service"))

    self.login_events: list[LoginEvent] = []
    self.unix_sockets: list[UnixSocket] = []
    self.firewall_rules: list[str] = ["22/tcp                     ALLOW       Anywhere"]

    self.last_exit_code = 0

    self._baseline_process_count = len(self.process_list)
    self._baseline_connection_count = len(self.network_connections)
    self._baseline_package_count = len(self.installed_packages)
    self._baseline_systemd_unit_count = len(self.systemd_units)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
      sys.path.insert(0, current_dir)
    
    self.commands: dict[str, Callable[..., str]] = {
      "pwd": self.do_pwd,
      "cd": self.do_cd,
      "sh": self.do_sh,
      "bash": self.do_sh,
      "crontab": self.do_crontab,
      "scp": self.do_scp,
      "ls": self.do_ls,
      "rm": self.do_rm,
      "cp": self.do_cp,
      "tee": self.do_tee,
      "set": self.do_set,
      "dd": self.do_dd,
      "mkdir": self.do_mkdir,
      "touch": self.do_touch,
      "rmdir": self.do_rmdir,
      "uptime": self.do_uptime,
      "free": self.do_free,
      "w": self.do_w,
      "who": self.do_who,
      "uname": self.do_uname,
      "which": self.do_which,
      "ps": self.do_ps,
      "grep": self.do_grep,
      "head": self.do_head,
      "tail": self.do_tail,
      "wc": self.do_wc,
      "ping": self.do_ping,
      "clear": self.do_clear,
      "env": self.do_env,
      "users": self.do_users,
      "wget": self.do_wget,
      "curl": self.do_curl,
      "tftp": self.do_tftp,
      "ftpget": self.do_ftpget,
      "nc": self.do_nc,
      "ncat": self.do_nc,
      "netcat": self.do_nc,
      "chown": self.do_chown,
      "chgrp": self.do_chgrp,
      "chmod": self.do_chmod,
      "exit": self.do_exit,
      "logout": self.do_exit,
      "kill": self.do_kill,
      "pkill": self.do_pkill,
      "killall": self.do_killall,
      "export": self.do_export,
      "unset": self.do_unset,
      "su": self.do_su,
      "netstat": self.do_netstat,
      "ss": self.do_ss,
      "ip": self.do_ip,
      "df": self.do_df,
      "mount": self.do_mount,
      "systemctl": self.do_systemctl,
      "journalctl": self.do_journalctl,
      "last": self.do_last,
      "lsof": self.do_lsof,
      "top": self.do_top,
      "sort": self.do_sort,
      "md5sum": self.do_md5sum,
      "sha1sum": self.do_sha1sum,
      "sha256sum": self.do_sha256sum,
      "stat": self.do_stat,
      "file": self.do_file,
      "basename": self.do_basename,
      "dirname": self.do_dirname,
      "realpath": self.do_realpath,
      "readlink": self.do_readlink,
      "ln": self.do_ln,
      "truncate": self.do_truncate,
      "xxd": self.do_xxd,
      "strings": self.do_strings,
      "sed": self.do_sed,
      "openssl": self.do_openssl,
      "usermod": self.do_usermod,
      "groupadd": self.do_groupadd,
      "groupdel": self.do_groupdel,
      "dpkg": self.do_dpkg,
      "lsblk": self.do_lsblk,
      "lsmod": self.do_lsmod,
      "dmesg": self.do_dmesg,
      "vmstat": self.do_vmstat,
      "ldd": self.do_ldd,
      "visudo": self.do_visudo,
      "at": self.do_at,
      "gzip": self.do_gzip,
      "bzip2": self.do_bzip2,
      "zip": self.do_zip,
      "ufw": self.do_ufw,
      "auditctl": self.do_auditctl,
      "systemd-run": self.do_systemd_run,
    }

    self._STDIN_AWARE_COMMANDS = {
      "grep", "head", "tail", "wc", "sort", "md5sum", "sha1sum", "sha256sum",
      "xxd", "strings", "sed", "openssl", "sh", "bash", "tee",
    }

    self.manipulated_output_commands: dict[str, str] = {}

    self._ensure_home_dir(self.current_user)
    self.environ = {
      "USER": self.current_user,
      "HOME": self._home_dir_for(self.current_user),
      "SHELL": "/bin/bash",
      "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "PWD": self.vfs.cwd_path,
      "TERM": "xterm-256color",
      "LANG": "en_US.UTF-8",
      "LOGNAME": self.current_user,
    }

    self.cowrie_registry: dict[str, type] = {}
    self.load_cowrie_commands()
    self.command_recorder = None

  def set_command_recorder(self, recorder):
    self.command_recorder = recorder

  def _should_record_command(self, command: str) -> bool:
    stripped_command = command.strip()
    return bool(stripped_command) and not re.match(r'^if(\s|\[)', stripped_command)

  def _record_command(self, command: str):
    if self.command_recorder and self._should_record_command(command):
      self.command_recorder(command.strip())
  
  @staticmethod
  def _home_dir_for(user: str) -> str:
    return "/root" if user == "root" else f"/home/{user}"

  def _ensure_home_dir(self, user: str) -> None:
    if user == "root":
      return
    uid = self._KNOWN_UIDS.get(user, 1000)
    gid = self._KNOWN_GIDS.get(user, uid)
    self.vfs.mkdir_p(self._home_dir_for(user), uid, gid, size=4096, mode="rwxr-xr-x")

  def set_current_user(self, user: str):
    self.current_user = user
    self.environ["USER"] = user
    self.environ["LOGNAME"] = user
    self._ensure_home_dir(user)
    home = self._home_dir_for(user)
    self.environ["HOME"] = home
    self.environ["PWD"] = home
    self.vfs.cwd_path = home
  
  _UNSUPPORTED_COWRIE_COMMANDS = frozenset({"busybox"})

  def load_cowrie_commands(self):
    try:
      import src.honeyengage.virtual_env.commands as cowrie_cmds_pkg

      for _, module_name, _ in pkgutil.iter_modules(cowrie_cmds_pkg.__path__):
        try:
          full_mod_name = f"src.honeyengage.virtual_env.commands.{module_name}"
          module = importlib.import_module(full_mod_name)

          if hasattr(module, 'commands') and isinstance(module.commands, dict):
            for cmd_string, cmd_class in module.commands.items():
              base_cmd = cmd_string.split('/')[-1]
              if base_cmd in self._UNSUPPORTED_COWRIE_COMMANDS:
                continue
              self.cowrie_registry[base_cmd] = cmd_class

        except Exception as e:
          logger.warning(f"Failed to load Cowrie command module '{module_name}': {e}")

      if "python" in self.cowrie_registry:
        self.cowrie_registry.setdefault("python3", self.cowrie_registry["python"])

    except Exception as e:
      logger.error(f"Fatal error initializing Cowrie registry: {e}")
  
  def get_motd(self):
    return (
      "Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)\r\n\r\n"
      " * Documentation:  https://help.ubuntu.com\r\n"
      " * Management:     https://landscape.canonical.com\r\n"
      " * Support:        https://ubuntu.com/pro\r\n\r\n"
      "  System information as of " + datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n\r\n"
      "  System load:  0.0                Processes:               113\r\n"
      "  Usage of /:   36.4% of 19.56GB   Users logged in:         0\r\n"
      "  Memory usage: 15%                IPv4 address for enp0s3: 10.0.2.15\r\n"
      "  Swamp usage:  0%\r\n\r\n"
      "Expanded security Maintenance for Applications is not enabled.\r\n\r\n"
      "0 updates can be applied immediately.\r\n\r\n"
      "Enable ESM Apps to receive additional future security updates.\r\n"
      "See https://ubuntu.com/esm or run: sudo pro status\r\n\r\n"
      "New release '24.04.4 LTS' available.\r\n"
      "Run 'do-release-upgrade' to upgrade to it.\r\n\r\n\r\n"
      "Last login: " + (datetime.now() - timedelta(days=1)).strftime("%a %b %d %H:%M:%S %Y") + " from 192.168.1.15\r\n"
    )
  
  def get_prompt(self):
    display_path = self.vfs.cwd_path
    home = self._home_dir_for(self.current_user)
    if (display_path == home):
      display_path = "~"
    elif display_path.startswith(f"{home}/"):
      display_path = "~" + display_path[len(home):]
    
    symbol = "#" if self.current_user == "root" else "$"
    return f"{self.current_user}@ubuntu:{display_path}{symbol} "
  
  def inject_fake_process(self, process_data: ProcessData):
    self.process_list.append(process_data)

  def inject_fake_network_connection(self, connection: dict):
    self.network_connections.append(NetworkConnection(**connection))

  def inject_fake_package(self, package: dict):
    self.installed_packages.append(InstalledPackage(**package))

  def inject_fake_network_interface(self, interface: dict):
    self.extra_network_interfaces.append(NetworkInterface(**interface))

  def inject_fake_systemd_unit(self, unit: dict):
    self.systemd_units.append(SystemdUnit(**unit))

  def inject_login_event(self, event: dict):
    self.login_events.append(LoginEvent(**event))

  def inject_fake_unix_socket(self, socket_info: dict):
    self.unix_sockets.append(UnixSocket(**socket_info))

  def reset_to_baseline(self) -> dict[str, int]:
    removed = {
      "processes": len(self.process_list) - self._baseline_process_count,
      "connections": len(self.network_connections) - self._baseline_connection_count,
      "packages": len(self.installed_packages) - self._baseline_package_count,
      "interfaces": len(self.extra_network_interfaces),
      "systemd_units": len(self.systemd_units) - self._baseline_systemd_unit_count,
      "login_events": len(self.login_events),
      "unix_sockets": len(self.unix_sockets),
    }
    self.process_list = self.process_list[:self._baseline_process_count]
    self.network_connections = self.network_connections[:self._baseline_connection_count]
    self.installed_packages = self.installed_packages[:self._baseline_package_count]
    self.extra_network_interfaces = []
    self.systemd_units = self.systemd_units[:self._baseline_systemd_unit_count]
    self.login_events = []
    self.unix_sockets = []
    return removed

  def _build_shutdown_output(self, mode: str) -> str:
    return (
      "\r\n"
      f"Broadcast message from root@ubuntu (pts/0) ({datetime.now().ctime()}):\r\n\r\n"
      f"The system is going down for {mode} NOW!\r\n"
    )

  def _check_termination(self, cmd: str, args: list[str]):
    normalized_cmd = posixpath.basename(cmd)
    normalized_args = {arg.lower() for arg in args}
    
    if normalized_cmd == "reboot":
      output = self._build_shutdown_output("reboot")
      raise ShellTerminationError(output, "System reboot requested")

    if normalized_cmd == "poweroff":
      output = self._build_shutdown_output("power off")
      raise ShellTerminationError(output, "System power off requested")

    if normalized_cmd == "shutdown":
      if "--help" in normalized_args or "-c" in normalized_args:
        return

      if "-r" in normalized_args or "--reboot" in normalized_args:
        output = self._build_shutdown_output("reboot")
        raise ShellTerminationError(output, "System reboot requested")

      output = self._build_shutdown_output("power off")
      raise ShellTerminationError(output, "System shutdown requested")
  
  def _handle_if_statement(self, command: str) -> str:
    match = re.search(
      r'^if\s+\[\s*(.+?)\s*\]\s*;\s*then\s+(.+?)\s*'
      r'((?:;\s*elif\s+\[\s*.+?\s*\]\s*;\s*then\s+.+?\s*)*)'
      r'(?:;\s*else\s+(.+?)\s*)?;\s*fi\s*;?\s*(.*)$',
      command, re.DOTALL | re.IGNORECASE,
    )

    if not match:
      return "bash: syntax error near unexpected token `fi'\n"

    branches: list[tuple[str, str]] = [(match.group(1).strip(), match.group(2).strip())]

    elif_blob = match.group(3) or ""
    for elif_match in re.finditer(
      r';\s*elif\s+\[\s*(.+?)\s*\]\s*;\s*then\s+(.+?)\s*(?=;\s*elif\s|\Z)',
      elif_blob, re.DOTALL | re.IGNORECASE,
    ):
      branches.append((elif_match.group(1).strip(), elif_match.group(2).strip()))

    else_block = match.group(4).strip() if match.group(4) else ""
    remainder = match.group(5).strip()

    output = ""
    matched_branch = False
    for condition, then_block in branches:
      if self._evaluate_condition(condition):
        output += self.execute_command(then_block)
        matched_branch = True
        break

    if not matched_branch and else_block:
      output += self.execute_command(else_block)

    if remainder:
      output += self.execute_command(remainder)

    return output

  def _evaluate_condition(self, condition: str) -> bool:
    def resolve_subshell(match):
      sub_cmd = match.group(1)
      return self.execute_command(sub_cmd).strip()

    condition = re.sub(r'\$\((.+?)\)', resolve_subshell, condition)
    condition = re.sub(r'`(.+?)`', resolve_subshell, condition)

    for var_name, var_value in self.environ.items():
      condition = condition.replace(f"${var_name}", var_value)

    condition = condition.replace('"', '').replace("'", "")

    parts = condition.split()
    if len(parts) == 3:
      left, op, right = parts
      if op in ('=', '=='):
        return left == right
      elif op == '!=':
        return left != right

    return False
  
  def _handle_sudo(self, command: str) -> str:
    cmd_clean = command.strip()
    
    remainder = re.sub(r'^sudo\s*', '', cmd_clean)
    
    if not remainder:
      return (
        "usage: sudo -h | -K | -k | -V\n"
        "usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\n"
        "usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\n"
        "usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]\n"
        "usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] file ...\n"
      )
    
    while True:
      match_param = re.match(r'^-([ugpU])\s+(?:"[^"]*"|\'[^\']*\'|\S+)\s*', remainder)
      match_simple = re.match(r'^-([A-Za-z]+)\s*', remainder)
      
      if match_param:
        remainder = remainder[match_param.end():]
      elif match_simple:
        remainder = remainder[match_simple.end():]
      else:
        break
            
    if not remainder:
      return ""
        
    return self.execute_command(remainder, record_current=False)

  _FAILURE_OUTPUT_PATTERNS = (
    "command not found",
    "No such file or directory",
    "not found",
    "cannot open",
    "cannot access",
    "internal error",
    "Permission denied",
    "syntax error",
    "Usage: ",
    "usage: ",
  )

  _SELF_REPORTING_EXIT_CODE_COMMANDS = frozenset({"which"})

  def _looks_like_failure(self, output: str) -> bool:
    return any(pattern in output for pattern in self._FAILURE_OUTPUT_PATTERNS)

  def _split_top_level(self, command: str, separators: tuple[str, ...]) -> list[tuple[str, str]]:
    tokens = sorted(separators, key=len, reverse=True)
    pattern = "|".join(re.escape(token) for token in tokens)
    matches = list(re.finditer(pattern, command))

    segments: list[tuple[str, str]] = []
    cursor = 0
    for match in matches:
      preceding = command[:match.start()]
      if (preceding.count('"') - preceding.count('\\"')) % 2 == 1:
        continue
      if (preceding.count("'") % 2) == 1:
        continue
      if preceding.count("(") != preceding.count(")"):
        continue
      if (preceding.count("`") % 2) == 1:
        continue
      segments.append((command[cursor:match.start()], match.group(0)))
      cursor = match.end()
    segments.append((command[cursor:], ""))
    return segments

  def execute_command(self, command: str, record_current: bool = True) -> str:
    command = command.strip()
    if not command:
      return ""

    if record_current:
      self._record_command(command)

    if command.startswith("if ") or command.startswith("if["):
      return self._handle_if_statement(command)

    output_parts: list[str] = []
    for statement, _ in self._split_top_level(command, (";",)):
      statement = statement.strip()
      if not statement:
        continue
      output_parts.append(self._execute_conditional_chain(statement))

    return "".join(output_parts)

  def _execute_conditional_chain(self, statement: str) -> str:
    stages = self._split_top_level(statement, ("&&", "||"))

    output_parts: list[str] = []
    should_run = True
    succeeded = True
    for stage, operator in stages:
      stage = stage.strip()
      if stage and should_run:
        output_parts.append(self._execute_pipeline(stage))
        succeeded = self.last_exit_code == 0

      if operator == "&&":
        should_run = succeeded
      elif operator == "||":
        should_run = not succeeded
      else:
        should_run = True

    return "".join(output_parts)

  def _execute_pipeline(self, segment: str) -> str:
    stages = [stage.strip() for stage, _ in self._split_top_level(segment, ("|",))]
    stages = [stage for stage in stages if stage]
    if not stages:
      return ""

    stdin: str | None = None
    output = ""
    for stage in stages:
      output = self._execute_single_command(stage, stdin=stdin)
      stdin = output
    return output

  _DOLLAR_PAREN_SUBST_RE = re.compile(r"\$\(")
  _BACKTICK_SUBST_RE = re.compile(r"`([^`]*)`")

  def _resolve_command_substitutions(self, text: str) -> str:
    result = []
    cursor = 0
    while cursor < len(text):
      dollar_match = self._DOLLAR_PAREN_SUBST_RE.search(text, cursor)
      backtick_match = self._BACKTICK_SUBST_RE.search(text, cursor)
      if dollar_match and (not backtick_match or dollar_match.start() < backtick_match.start()):
        depth = 1
        i = dollar_match.end()
        while i < len(text) and depth > 0:
          if text[i] == "(":
            depth += 1
          elif text[i] == ")":
            depth -= 1
          i += 1
        inner_command = text[dollar_match.end():i - 1]
        result.append(text[cursor:dollar_match.start()])
        output = self._execute_conditional_chain(inner_command)
        result.append(output[:-1] if output.endswith("\n") else output)
        cursor = i
      elif backtick_match:
        result.append(text[cursor:backtick_match.start()])
        output = self._execute_conditional_chain(backtick_match.group(1))
        result.append(output[:-1] if output.endswith("\n") else output)
        cursor = backtick_match.end()
      else:
        result.append(text[cursor:])
        break
    return "".join(result)

  def _execute_single_command(self, command: str, stdin: str | None = None) -> str:
    command = command.strip()
    if not command:
      return ""

    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*=', command):
      var_name, var_value = command.split('=', 1)
      var_value = self._resolve_command_substitutions(var_value)
      self.environ[var_name] = var_value.replace('"', '').replace("'", "")
      self.last_exit_code = 0
      return ""

    if command.startswith("if ") or command.startswith("if["):
      return self._handle_if_statement(command)

    if command.startswith("sudo ") or command == "sudo":
      return self._handle_sudo(command)

    home = self.environ.get("HOME", "/root")
    command = re.sub(r'(^|[\s=:])~(?=/|\s|$)', lambda m: m.group(1) + home, command)

    for var_name, var_value in self.environ.items():
      command = command.replace(f"${var_name}", var_value)

    command = re.sub(r'\$[a-zA-Z_][a-zA-Z0-9_]*', '', command)

    redirect_file = None
    is_append = False

    try:
      parts = shlex.split(command.strip(), posix=True)
    except ValueError:
      parts = command.strip().split()
    for index, token in enumerate(parts):
      if token == '>>':
        redirect_file = parts[index + 1] if index + 1 < len(parts) else ""
        is_append = True
        parts = parts[:index]
        break
      if token == '>':
        redirect_file = parts[index + 1] if index + 1 < len(parts) else ""
        parts = parts[:index]
        break
      if token.startswith('>>') and len(token) > 2:
        redirect_file = token[2:]
        is_append = True
        parts = parts[:index]
        break
      if token.startswith('>') and len(token) > 1:
        redirect_file = token[1:]
        parts = parts[:index]
        break

    if not parts:
      return ""

    cmd = posixpath.basename(parts[0])
    args = parts[1:]

    self._check_termination(cmd, args)

    output = ""

    if cmd in self.manipulated_output_commands:
      output = self.manipulated_output_commands[cmd]
    elif cmd in self.commands:
      try:
        output = self.commands[cmd](args, stdin=stdin) if cmd in self._STDIN_AWARE_COMMANDS else self.commands[cmd](args)
      except Exception as e:
        logger.error(f"Error executing command '{cmd}': {e}\r\n")
        output = f"Error: {e}"
    else:
      output = self.execute_cowrie_command(cmd, args, stdin=stdin)

    if cmd not in self._SELF_REPORTING_EXIT_CODE_COMMANDS:
      self.last_exit_code = 1 if self._looks_like_failure(output) else 0

    if redirect_file:
      virtual_path = self.vfs.resolve_path(redirect_file, self.vfs.cwd_path)
      output_to_write = (output if output else "").replace("\r\n", "\n")
      if self.vfs.get_node(virtual_path) is None:
        uid = 0
        gid = 0
        size = len(output_to_write)
        mode = "-rw-r--r--"
        realfile = os.path.join("honeyfs", virtual_path.lstrip("/"))
        self.vfs.mkfile_p(virtual_path, uid, gid, size, mode, realfile)

      node = self.vfs.get_node(virtual_path)

      if not isinstance(node, FSFile):
        return ""

      if is_append:
        new_content = node.content + output_to_write
        node.content = new_content
        node.size = len(node.content)
      else:
        node.content = output_to_write
        node.size = len(node.content)
    if redirect_file:
      return ""
    return output

  def execute_cowrie_command(self, cmd_name: str, args: list, stdin: str | None = None):
    CommandClass = self.cowrie_registry.get(cmd_name)

    if not CommandClass:
      return f"bash: {cmd_name}: command not found\r\n"

    try:
      uid = self._KNOWN_UIDS.get(self.current_user, 1000)
      gid = self._KNOWN_GIDS.get(self.current_user, uid)
      mock_protocol = MockProtocol(self.vfs, current_user=self.current_user, uid=uid, gid=gid)
      cmd_instance = CommandClass(mock_protocol, *args)
      cmd_instance.set_input_data((stdin or "").encode("utf-8"))
      cmd_instance.start()

      if cmd_name == "ping" and getattr(cmd_instance, "running", False):
        if getattr(cmd_instance, "max", 0) <= 0:
          cmd_instance.max = 4

        while getattr(cmd_instance, "running", False):
          cmd_instance.showreply()
            
      raw_output = cmd_instance.output_buffer

      clean_output = raw_output.replace('\r\n', '\n').replace('\n', '\r\n')
            
      return clean_output

    except Exception as e:
      logger.error(f"Error executing Cowrie mock for {cmd_name}: {e}")
      return f"bash: {cmd_name}: internal error\r\n"
  
  def manipulate_command_output(self, cmd_name: str, output: str) -> bool:
    if cmd_name in ["ls", "pwd", "cd", "mkdir", "rmdir", "touch", "rm"]:
      return False
    if isinstance(output, dict):
      output = "\n".join(f"{k}: {v}" for k, v in output.items())
    elif isinstance(output, (list, tuple)):
      output = "\n".join(str(item) for item in output)
    elif not isinstance(output, str):
      output = str(output)
    self.manipulated_output_commands.setdefault(cmd_name, output)
    return True


  def do_scp(self, args: list):
    remote_targets = [a for a in args if not a.startswith("-") and "@" in a]
    host = remote_targets[0].split("@", 1)[1].split(":", 1)[0] if remote_targets else "unknown-host"
    return f"ssh: Could not resolve hostname {host}: Name or service not known\r\n"

  def do_pwd(self, args: list):
    return self.vfs.cwd_path + "\r\n"

  def do_sh(self, args: list, stdin: str | None = None):
    self._sh_depth = getattr(self, "_sh_depth", 0)
    if self._sh_depth >= 5:
      return "sh: too many levels of recursion\r\n"

    if args and args[0] == "-c":
      script = " ".join(args[1:])
      if len(script) >= 2 and script[0] == script[-1] and script[0] in ("'", '"'):
        script = script[1:-1]
    elif stdin:
      script = stdin
    elif args:
      target = self.vfs.resolve_path(args[0], self.vfs.cwd_path)
      node = self.vfs.get_node(target)
      if node is None:
        return f"sh: {args[0]}: No such file or directory\r\n"
      raw_content = self.vfs.file_contents(target) or b""
      script = raw_content.decode("utf-8", errors="replace") if isinstance(raw_content, bytes) else raw_content
    else:
      return ""

    executable_lines = [
      line.strip() for line in script.splitlines()
      if line.strip() and not line.strip().startswith("#")
    ]
    script = "; ".join(executable_lines)
    if not script:
      return ""

    self._sh_depth += 1
    try:
      return self.execute_command(script, record_current=False)
    finally:
      self._sh_depth -= 1

  def do_crontab(self, args: list):
    if "-l" in args:
      return f"no crontab for {self.current_user}\r\n"
    if "-r" in args:
      return ""
    file_args = [a for a in args if not a.startswith("-")]
    if file_args:
      target = self.vfs.resolve_path(file_args[0], self.vfs.cwd_path)
      if self.vfs.get_node(target) is None:
        return f"crontab: {file_args[0]}: No such file or directory\r\n"
      return ""
    return "crontab: usage error: file name must be specified for replace\r\n"


  def do_cd(self, args: list):
    target_path = self._home_dir_for(self.current_user) if not args else args[0]


    new_path = posixpath.normpath(posixpath.join(self.vfs.cwd_path, target_path))
    
    node = self.resolve_absolute_path(new_path)

    if node is None:
      return f"-bash: cd: {target_path}: No such file or directory\r\n"
    if isinstance(node, FSDirectory):
      self.vfs.current_directory = node
      self.vfs.cwd_path = new_path
      return ""
    else:
      return f"-bash: cd: {target_path}: Not a directory\r\n"
  
  def resolve_absolute_path(self, target_path: str):
    if target_path == "/":
      return self.vfs.root

    parts = target_path.strip("/").split("/")
    node: FSNode = self.vfs.root
    for part in parts:
      if isinstance(node, FSDirectory) and part in node.children:
        node = node.children[part]
      else:
        return None
    return node
  
  def do_ls(self, args: list):
    targets = [arg for arg in args if not arg.startswith('-')]

    if not targets:
      target_dir = self.vfs.current_directory
    else:
      target_path = posixpath.normpath(posixpath.join(self.vfs.cwd_path, targets[0]))
      node = self.resolve_absolute_path(target_path)
      if node is None:
        return f"ls: cannot access '{targets[0]}': No such file or directory\r\n"
      if not isinstance(node, FSDirectory):
        return targets[0] + "\r\n"
      target_dir = node

    if not target_dir.children:
      return ""
    names = [nodo.name for nodo in target_dir.children.values()]

    return "  ".join(names) + "\r\n"
  
  def do_rm(self, args: list):
    if not args:
      return "rm: missing operand\n"
    
    files_to_delete = [arg for arg in args if not arg.startswith('-')]
    
    if not files_to_delete:
      return ""

    output = ""
    for filename in files_to_delete:
      virtual_path = self.vfs.resolve_path(filename, self.vfs.cwd_path)

      if self.vfs.get_node(virtual_path) is None:
        output += f"rm: cannot remove '{filename}': No such file or directory\r\n"
        continue
      elif isinstance(self.vfs.get_node(virtual_path), FSDirectory):
        output += f"rm: cannot remove '{filename}': Is a directory\r\n"
        continue
      
      success = self.vfs.delete_node(virtual_path)
      
      if not success:
        output += f"rm: cannot remove '{filename}': No such file or directory\r\n"
            
    return output
  
  def do_mkdir(self, args: list):
    if not args:
      return "mkdir: missing operand\n"
    
    output = ""
    for dirname in args:
      virtual_path = self.vfs.resolve_path(dirname, self.vfs.cwd_path)
      
      if self.vfs.get_node(virtual_path) is not None:
        output += f"mkdir: cannot create directory '{dirname}': File exists\r\n"
        continue
      
      self.vfs.mkdir(virtual_path, uid=0, gid=0, size=4096, mode="drwxr-xr-x")
    
    return output
  
  def do_touch(self, args: list):
    if not args:
      return "touch: missing file operand\n"
    
    output = ""
    for filename in args:
      virtual_path = self.vfs.resolve_path(filename, self.vfs.cwd_path)
      
      if self.vfs.get_node(virtual_path) is not None:
        continue
      
      self.vfs.mkfile_p(virtual_path, uid=0, gid=0, size=0, mode="-rw-r--r--")
    
    return output
  
  def do_rmdir(self, args: list):
    if not args:
      return "rmdir: missing operand\n"
    
    output = ""
    for dirname in args:
      virtual_path = self.vfs.resolve_path(dirname, self.vfs.cwd_path)
      
      node = self.vfs.get_node(virtual_path)
      
      if node is None:
        output += f"rmdir: failed to remove '{dirname}': No such file or directory\r\n"
        continue

      if not isinstance(node, FSDirectory):
        output += f"rmdir: failed to remove '{dirname}': Not a directory\r\n"
        continue
      
      if node.children:
        output += f"rmdir: failed to remove '{dirname}': Directory not empty\r\n"
        continue
      
      success = self.vfs.delete_node(virtual_path)
      
      if not success:
        output += f"rmdir: failed to remove '{dirname}': No such file or directory\r\n"
            
    return output
  
  def do_uptime(self, args: list):
    return " 16:20:00 up 2 days,  4:30,  1 user,  load average: 0.00, 0.01, 0.05\n"
  
  def do_free(self, args: list):
    return (
      "              total        used        free      shared  buff/cache   available\n"
      "Mem:        2010780      300000     1451796       50000       23944     1638988\n"
      "Swap:       2097148           0     2097148\n"
    )
  
  def do_w(self, args: list):
    return (
      " 16:20:00 up 2 days,  4:30,  1 user,  load average: 0.00, 0.01, 0.05\n"
      "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
      "root     pts/0    192.168.1.100    16:00    1.00s  0.02s  0.00s w\n"
    )
  
  def do_who(self, args: list):
    return "root     pts/0        2026-05-27 16:00 (192.168.1.100)\n"

  _KNOWN_BINARIES: dict[str, str] = {
    "python3": "/usr/bin/python3",
    "bash": "/bin/bash",
    "sh": "/bin/sh",
    "curl": "/usr/bin/curl",
    "wget": "/usr/bin/wget",
    "perl": "/usr/bin/perl",
    "awk": "/usr/bin/awk",
    "grep": "/bin/grep",
    "sed": "/bin/sed",
    "systemctl": "/bin/systemctl",
    "cron": "/usr/sbin/cron",
    "crontab": "/usr/bin/crontab",
    "ssh": "/usr/bin/ssh",
    "scp": "/usr/bin/scp",
    "nc": "/bin/nc",
  }

  def do_which(self, args: list):
    if not args:
      return ""
    lines = []
    for name in args:
      path = self._KNOWN_BINARIES.get(name)
      if not path and (name in self.commands or name in self.cowrie_registry):
        path = f"/usr/bin/{name}"
      if path:
        lines.append(path)
    self.last_exit_code = 0 if len(lines) == len(args) else 1
    return "\n".join(lines) + ("\n" if lines else "")

  def do_uname(self, args: list):
    if "-a" in args:
      return "Linux ubuntu 6.8.0-49-generic #49-Ubuntu SMP x86_64 GNU/Linux\n"
    if "-r" in args:
      return "6.8.0-49-generic\n"
    if "-m" in args:
      return "x86_64\n"
    if "-n" in args:
      return "ubuntu\n"
    return "Linux\n"
  
  def do_ps(self, args: list):
    columns: list[str] = ["USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND"]
    field_map = {
      "USER": "user",
      "PID": "pid",
      "%CPU": "cpu_usage",
      "%MEM": "memory_usage",
      "VSZ": "vsz",
      "RSS": "rss",
      "TTY": "tty",
      "STAT": "stat",
      "START": "start_time",
      "TIME": "time",
      "COMMAND": "command",
    }

    command_name = "ps" if not args else f"ps {' '.join(args)}"
    ps_process = ProcessData(
      user=self.current_user,
      pid=randint(1000, 2000),
      cpu_usage=0.1,
      memory_usage=0.5,
      vsz=10276,
      rss=3860,
      tty=self.current_tty,
      stat="R+",
      start_time=datetime.now().strftime("%H:%M"),
      time="0:00",
      command=command_name
    )
    self.process_list.append(ps_process)

    try:
      normalized_args = [arg.lstrip("-") for arg in args if arg and arg != "--"]
      option_flags = "".join(arg for arg in normalized_args if arg.isalpha()).lower()

      if not normalized_args:
        columns_to_show = ["PID", "TTY", "TIME", "COMMAND"]
      elif "aux" in normalized_args or option_flags == "aux" or set(option_flags) >= {"a", "u", "x"} or "ef" in normalized_args or option_flags == "ef" or set(option_flags) >= {"e", "f"}:
        columns_to_show = columns
      else:
        requested_columns = {arg.upper() for arg in normalized_args}
        columns_to_show = [col for col in columns if col in requested_columns]
        if not columns_to_show:
          columns_to_show = ["PID", "TTY", "TIME", "COMMAND"]

      visible_processes = self.process_list
      if not normalized_args:
        visible_processes = [
          proc for proc in self.process_list
          if proc.user == self.current_user and proc.tty == self.current_tty
        ]

      rendered_rows: list[dict[str, str]] = []
      column_widths = {col: len(col) for col in columns_to_show}

      for proc in visible_processes:
        proc_dict = proc.model_dump()
        rendered_row = {}
        for col in columns_to_show:
          value = str(proc_dict[field_map[col]])
          if col in {"%CPU", "%MEM"}:
            value = f"{float(value):.1f}"
          rendered_row[col] = value
          column_widths[col] = max(column_widths[col], len(value))
        rendered_rows.append(rendered_row)

      output_lines = [
        "  ".join(
          col.rjust(column_widths[col]) if col in {"PID", "VSZ", "RSS", "%CPU", "%MEM"}
          else col.ljust(column_widths[col])
          for col in columns_to_show
        )
      ]

      for rendered_row in rendered_rows:
        line_parts = []
        for col in columns_to_show:
          value = rendered_row[col]
          if col in {"PID", "VSZ", "RSS", "%CPU", "%MEM"}:
            line_parts.append(value.rjust(column_widths[col]))
          else:
            line_parts.append(value.ljust(column_widths[col]))
        output_lines.append("  ".join(line_parts))

      return "\r\n".join(output_lines) + "\r\n"
    finally:
      if ps_process in self.process_list:
        self.process_list.remove(ps_process)
  
  def do_grep(self, args: list, stdin: str | None = None):
    try:
      _, clean_args = getopt.getopt(args, "")
    except Exception:
      clean_args = [a for a in args if not a.startswith('-')]

    if len(clean_args) < 1:
      return "Usage: grep [OPTIONS] PATTERN [FILE...]\n"

    pattern = clean_args[0]
    files = clean_args[1:]

    if not files:
      if stdin is None:
        return "Usage: grep [OPTIONS] PATTERN [FILE...]\n"
      return "".join(f"{line}\n" for line in stdin.split('\n') if pattern in line)

    output = ""
    for file in files:
      try:
        virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
        content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
        for line in content.split('\n'):
          if pattern in line:
            output += f"{line}\n"
      except Exception:
        output += f"grep: {file}: No such file or directory\n"
    return output

  def do_head(self, args: list, stdin: str | None = None):
    try:
      optlist, clean_args = getopt.getopt(args, "n:")
    except Exception:
      return "Usage: head [OPTIONS] FILE\n"

    line_count = 10
    for opt, opt_value in optlist:
      if opt == "-n":
        try:
          line_count = int(opt_value)
        except ValueError:
          return "Usage: head [OPTIONS] FILE\n"

    if not clean_args:
      if stdin is None:
        return "Usage: head [OPTIONS] FILE\n"
      lines = stdin.splitlines()[:line_count]
      output = "\n".join(lines)
      return output + "\n" if output else ""

    file = clean_args[0]
    output = ""

    try:
      virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      lines = content.splitlines()[:line_count]
      output = "\n".join(lines)
      if output:
        output += "\n"
    except Exception:
      output += f"head: cannot open '{file}' for reading: No such file or directory\n"

    return output

  def do_tail(self, args: list, stdin: str | None = None):
    try:
      optlist, clean_args = getopt.getopt(args, "n:")
    except Exception:
      return "Usage: tail [OPTIONS] FILE\n"

    line_count = 10
    for opt, opt_value in optlist:
      if opt == "-n":
        try:
          line_count = int(opt_value)
        except ValueError:
          return "Usage: tail [OPTIONS] FILE\n"

    if not clean_args:
      if stdin is None:
        return "Usage: tail [OPTIONS] FILE\n"
      lines = stdin.splitlines()[-line_count:]
      output = "\n".join(lines)
      return output + "\n" if output else ""

    file = clean_args[0]
    output = ""

    try:
      virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      lines = content.splitlines()[-line_count:]
      output = "\n".join(lines)
      if output:
        output += "\n"
    except Exception:
      output += f"tail: cannot open '{file}' for reading: No such file or directory\n"

    return output

  def do_wc(self, args: list, stdin: str | None = None):
    try:
      optlist, clean_args = getopt.getopt(args, "cmlwhv")
    except Exception:
      return "Usage: wc [OPTIONS] FILE\n"

    selected_options = {opt for opt, _ in optlist}

    def format_counts(content: str, label: str | None) -> str:
      lines = content.count("\n")
      words = len(content.split())
      chars = len(content.encode("utf-8"))

      selected_counts = []
      if not selected_options or "-l" in selected_options:
        selected_counts.append(str(lines))
      if not selected_options or "-w" in selected_options:
        selected_counts.append(str(words))
      if not selected_options or "-c" in selected_options or "-m" in selected_options:
        selected_counts.append(str(chars))

      if label is None:
        return f"{' '.join(selected_counts)}\n"
      return f"{' '.join(selected_counts)} {label}\n"

    if not clean_args:
      if stdin is None:
        return "Usage: wc [OPTIONS] FILE\n"
      return format_counts(stdin, None)

    file = clean_args[0]

    try:
      virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      return format_counts(content, file)
    except Exception:
      return f"wc: cannot open '{file}' for reading: No such file or directory\n"

  def do_ping(self, args: list):
    try:
      optlist, remaining_args = getopt.getopt(args, "c:i:")
    except Exception:
      return "ping: invalid arguments\n"

    if not remaining_args:
      return (
        "Usage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]\n"
        "            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]\n"
        "            [-M mtu discovery hint] [-S sndbuf]\n"
        "            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination\n"
      )

    host = remaining_args[0].strip()
    packet_count = 4

    for opt, opt_value in optlist:
      if opt == "-c":
        try:
          packet_count = int(opt_value)
        except Exception:
          packet_count = 0

    if packet_count <= 0:
      return "ping: bad number of packets to transmit.\n"

    try:
      socket.inet_aton(host)
      ip_address = host
    except Exception:
      digest = hashlib.md5(host.encode("utf-8")).hexdigest()
      ip_address = ".".join(str(int(digest[index:index + 2], 16)) for index in range(0, 8, 2))

    output_lines = [f"PING {host} ({ip_address}) 56(84) bytes of data."]

    for seq in range(1, packet_count + 1):
      output_lines.append(
        f"64 bytes from {host} ({ip_address}): icmp_seq={seq} ttl=50 time={40.0 + seq / 10:.1f} ms"
      )

    output_lines.append("")
    output_lines.append(f"--- {host} ping statistics ---")
    output_lines.append(
      f"{packet_count} packets transmitted, {packet_count} received, 0% packet loss, time 907ms"
    )
    output_lines.append("rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms")

    return "\n".join(output_lines) + "\n"
  
  def do_clear(self, args: list):
    return "\033[H\033[J"

  def do_env(self, args: list):
    output_lines = [f"{key}={value}" for key, value in self.environ.items()]
    return "\n".join(output_lines) + "\n"

  def do_users(self, args: list):
    return f"{self.current_user}\n"


  def _guess_download_filename(self, source: str) -> str:
    path_part = source.split("?", 1)[0].rstrip("/")
    candidate = posixpath.basename(path_part)
    return candidate or "index.html"

  def _simulate_downloaded_file(self, output_path: str) -> None:
    fake_content = (
      b"#!/bin/sh\n"
      b"# placeholder payload retrieved by ingress tool transfer\n"
      b"echo ok\n"
    )
    virtual_path = self.vfs.resolve_path(output_path, self.vfs.cwd_path)
    if self.vfs.get_node(virtual_path) is None:
      self.vfs.mkfile_p(virtual_path, uid=0, gid=0, size=len(fake_content), mode="-rwxr-xr-x")
    self.vfs.override_file_contents(virtual_path, fake_content)

  def do_wget(self, args: list):
    try:
      optlist, remaining_args = getopt.getopt(
        args, "O:o:qP:", ["output-document=", "directory-prefix="]
      )
    except Exception:
      return "wget: invalid option\n"

    if not remaining_args:
      return "wget: missing URL\n"

    url = remaining_args[0]
    output_path = None
    for opt, opt_value in optlist:
      if opt in ("-O", "--output-document"):
        output_path = opt_value

    if output_path is None:
      output_path = self._guess_download_filename(url)

    self._simulate_downloaded_file(output_path)
    resolved_name = posixpath.basename(self.vfs.resolve_path(output_path, self.vfs.cwd_path))

    return (
      f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
      f"Resolving host... connected.\n"
      "HTTP request sent, awaiting response... 200 OK\n"
      f"Saving to: '{resolved_name}'\n\n"
      f"{resolved_name}   100%[===================>]\n\n"
      f"'{resolved_name}' saved\n"
    )

  def do_curl(self, args: list):
    try:
      optlist, remaining_args = getopt.getopt(
        args, "O o:sL", ["output=", "silent", "location"]
      )
    except Exception:
      return "curl: invalid option\n"

    if not remaining_args:
      return "curl: try 'curl --help' for more information\n"

    url = remaining_args[0]
    output_path = None
    write_to_stdout = True
    for opt, opt_value in optlist:
      if opt == "-O":
        output_path = self._guess_download_filename(url)
        write_to_stdout = False
      elif opt in ("-o", "--output"):
        output_path = opt_value
        write_to_stdout = False

    if output_path is not None:
      self._simulate_downloaded_file(output_path)
      return ""

    if write_to_stdout:
      return "<!doctype html>\n<html><head><title>OK</title></head><body>ok</body></html>\n"
    return ""

  def do_tftp(self, args: list):
    try:
      optlist, remaining_args = getopt.getopt(args, "i", ["get=", "put="])
    except Exception:
      return "tftp: invalid option\n"

    get_target = None
    for opt, opt_value in optlist:
      if opt == "--get":
        get_target = opt_value

    if get_target is None and remaining_args:
      is_put = any(arg.upper() == "PUT" for arg in remaining_args)
      if not is_put:
        get_target = remaining_args[-1]

    if get_target is None:
      return "usage: tftp [-i] host [port] [-c command]\n"

    self._simulate_downloaded_file(self._guess_download_filename(get_target))
    return ""

  def do_ftpget(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if len(clean_args) < 3:
      return "Usage: ftpget [options] host local-file remote-file\n"

    local_file = clean_args[1]
    self._simulate_downloaded_file(local_file)
    return ""

  def do_nc(self, args: list):
    try:
      optlist, remaining_args = getopt.getopt(args, "lnvzp:w:")
    except Exception:
      return "usage: nc [-46lnruz] [-p source_port] hostname port\n"

    is_listener = any(opt == "-l" for opt, _ in optlist)

    if is_listener:
      port = next((value for opt, value in optlist if opt == "-p"), None)
      port = port or (remaining_args[0] if remaining_args else "?")
      return f"listening on [any] {port} ...\n"

    if len(remaining_args) < 2:
      return "usage: nc [-46lnruz] [-p source_port] hostname port\n"

    host, port = remaining_args[0], remaining_args[1]
    is_verbose = any(opt == "-v" for opt, _ in optlist)
    if is_verbose:
      return f"nc: connect to {host} port {port} (tcp) failed: Connection refused\n"
    return ""

  _KNOWN_UIDS = {
    "root": 0, "daemon": 1, "bin": 2, "sys": 3, "www-data": 33,
    "nobody": 65534, "daniel": 1000, "lxd": 999,
  }
  _KNOWN_GIDS = {
    "root": 0, "daemon": 1, "bin": 2, "sys": 3, "www-data": 33,
    "nogroup": 65534, "daniel": 1000, "lxd": 100,
  }

  def _resolve_owner_spec(self, spec: str) -> tuple[int | None, int | None]:
    user_part, _, group_part = spec.partition(":")

    def resolve(name: str, table: dict[str, int]) -> int | None:
      if not name:
        return None
      if name.isdigit():
        return int(name)
      if name in table:
        return table[name]
      return 1000 + (hash(name) % 8999)

    uid = resolve(user_part, self._KNOWN_UIDS) if user_part else None
    gid = resolve(group_part, self._KNOWN_GIDS) if group_part else None
    return uid, gid

  def do_exit(self, args: list):
    return ""

  def do_chmod(self, args: list):
    clean_args = [a for a in args if not (a.startswith('-') and a not in ('-', ))]
    if len(clean_args) < 2:
      return "chmod: missing operand\nTry 'chmod --help' for more information.\n"

    mode_spec, paths = clean_args[0], clean_args[1:]

    output = ""
    for path in paths:
      virtual_path = self.vfs.resolve_path(path, self.vfs.cwd_path)
      node = self.vfs.get_node(virtual_path)
      if node is None:
        output += f"chmod: cannot access '{path}': No such file or directory\n"
        continue
      new_permissions = self._apply_chmod_spec(node.permissions, mode_spec)
      if new_permissions is None:
        return f"chmod: invalid mode: '{mode_spec}'\nTry 'chmod --help' for more information.\n"
      self.vfs.override_file_metadata(virtual_path, {"permissions": new_permissions})
    return output

  def _apply_chmod_spec(self, current_permissions: str, mode_spec: str) -> str | None:
    if not isinstance(current_permissions, str):
      current_permissions = "-rwxr-xr-x"
    type_char = current_permissions[0] if current_permissions else "-"
    rwx = list(current_permissions[1:10]) if len(current_permissions) >= 10 else list("rwxr-xr-x")

    if re.fullmatch(r"[0-7]{3,4}", mode_spec):
      octal = mode_spec[-3:]
      bits = ""
      for digit in octal:
        n = int(digit)
        bits += ("r" if n & 4 else "-") + ("w" if n & 2 else "-") + ("x" if n & 1 else "-")
      return type_char + bits

    groups = {"u": (0, 3), "g": (3, 6), "o": (6, 9)}
    for clause in mode_spec.split(","):
      m = re.fullmatch(r"([ugoa]*)([-+=])([rwxst]*)", clause)
      if not m:
        return None
      who, op, perm = m.group(1) or "a", m.group(2), m.group(3)
      targets = ["u", "g", "o"] if who == "a" else list(who)
      for target in targets:
        if target not in groups:
          return None
        start, end = groups[target]
        if op == "=":
          for i, letter in enumerate("rwx"):
            rwx[start + i] = letter if letter in perm else "-"
        else:
          for letter in perm:
            if letter in "rwx":
              idx = start + "rwx".index(letter)
              rwx[idx] = letter if op == "+" else "-"
        if "s" in perm and target in ("u", "g"):
          exec_idx = start + 2
          if op == "-":
            rwx[exec_idx] = "x" if rwx[exec_idx] in ("s", "S") else rwx[exec_idx]
          else:
            rwx[exec_idx] = "s" if rwx[exec_idx] == "x" else "S"
        if "t" in perm and target == "o":
          exec_idx = 8
          if op == "-":
            rwx[exec_idx] = "x" if rwx[exec_idx] in ("t", "T") else rwx[exec_idx]
          else:
            rwx[exec_idx] = "t" if rwx[exec_idx] == "x" else "T"
    return type_char + "".join(rwx)

  def do_chown(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if len(clean_args) < 2:
      return "Usage: chown [OPTION]... OWNER[:GROUP] FILE...\n"

    owner_spec, paths = clean_args[0], clean_args[1:]
    uid, gid = self._resolve_owner_spec(owner_spec)

    output = ""
    for path in paths:
      virtual_path = self.vfs.resolve_path(path, self.vfs.cwd_path)
      if self.vfs.get_node(virtual_path) is None:
        output += f"chown: cannot access '{path}': No such file or directory\n"
        continue
      new_metadata: dict[str, int] = {}
      if uid is not None:
        new_metadata["uid"] = uid
      if gid is not None:
        new_metadata["gid"] = gid
      self.vfs.override_file_metadata(virtual_path, new_metadata)
    return output

  def do_chgrp(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if len(clean_args) < 2:
      return "Usage: chgrp [OPTION]... GROUP FILE...\n"
    group, paths = clean_args[0], clean_args[1:]
    output = ""
    for path in paths:
      virtual_path = self.vfs.resolve_path(path, self.vfs.cwd_path)
      node = self.vfs.get_node(virtual_path)
      if node is None:
        output += f"chgrp: cannot access '{path}': No such file or directory\n"
        continue
      gid = self._resolve_owner_spec(f":{group}")[1]
      self.vfs.override_file_metadata(virtual_path, {"gid": gid})
    return output

  def do_kill(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "usage: kill [-s sigspec | -signum] pid | jobspec ... \n"

    output = ""
    for target in clean_args:
      if not target.isdigit():
        continue
      pid = int(target)
      before = len(self.process_list)
      self.process_list = [p for p in self.process_list if p.pid != pid]
      if len(self.process_list) == before:
        output += f"kill: ({pid}): No such process\n"
    return output

  def do_pkill(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "usage: pkill [-signal] pattern\n"
    pattern = clean_args[-1]
    self.process_list = [p for p in self.process_list if pattern not in p.command]
    return ""

  def do_killall(self, args: list):
    return self.do_pkill(args)

  def do_export(self, args: list):
    for arg in args:
      if "=" in arg:
        var_name, var_value = arg.split("=", 1)
        self.environ[var_name] = var_value.strip('"').strip("'")
    return ""

  def do_unset(self, args: list):
    for arg in args:
      self.environ.pop(arg, None)
    return ""

  def do_su(self, args: list):
    if "-c" in args:
      c_index = args.index("-c")
      clean_args = [a for a in args[:c_index] if not a.startswith('-')]
      target_user = clean_args[0] if clean_args else "root"
      script = " ".join(args[c_index + 1:])
      if len(script) >= 2 and script[0] == script[-1] and script[0] in ("'", '"'):
        script = script[1:-1]

      original_user = self.current_user
      original_cwd = self.vfs.cwd_path
      self.set_current_user(target_user)
      try:
        return self.execute_command(script, record_current=False)
      finally:
        self.set_current_user(original_user)
        self.vfs.cwd_path = original_cwd

    clean_args = [a for a in args if not a.startswith('-')]
    target_user = clean_args[0] if clean_args else "root"
    self.set_current_user(target_user)
    return ""


  def do_netstat(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    show_listening_only = any(a.startswith('-') and 'l' in a for a in args)

    header = f"{'Proto':<6}{'Recv-Q':<8}{'Send-Q':<8}{'Local Address':<23}{'Foreign Address':<23}{'State':<12}\n"
    lines = [header.rstrip("\n")]
    for conn in self.network_connections:
      if show_listening_only and conn.state != "LISTEN":
        continue
      lines.append(
        f"{conn.protocol:<6}{'0':<8}{'0':<8}{conn.local_address:<23}{conn.remote_address:<23}{conn.state:<12}"
      )

    if clean_args and clean_args[0] == "route":
      return (
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        "0.0.0.0         10.0.2.2        0.0.0.0         UG    0      0        0 eth0\n"
        "10.0.2.0        0.0.0.0         255.255.255.0   U     0      0        0 eth0\n"
      )

    return "\n".join(lines) + "\n"

  def do_ss(self, args: list):
    show_listening_only = any(a.startswith('-') and 'l' in a for a in args)
    tcp_only = any(a.startswith('-') and 't' in a for a in args)
    udp_only = any(a.startswith('-') and 'u' in a for a in args)

    header = f"{'Netid':<6}{'State':<12}{'Recv-Q':<8}{'Send-Q':<8}{'Local Address:Port':<24}{'Peer Address:Port':<24}\n"
    lines = [header.rstrip("\n")]
    for conn in self.network_connections:
      if show_listening_only and conn.state != "LISTEN":
        continue
      protocol = conn.protocol.lower()
      if tcp_only and protocol != "tcp":
        continue
      if udp_only and protocol != "udp":
        continue
      lines.append(
        f"{protocol:<6}{conn.state:<12}{'0':<8}{'0':<8}{conn.local_address:<24}{conn.remote_address:<24}"
      )

    return "\n".join(lines) + "\n"

  def do_ip(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: ip [OPTIONS] OBJECT { COMMAND | help }\n"

    subject = clean_args[0]

    if subject in ("addr", "address", "a"):
      output = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "       valid_lft forever preferred_lft forever\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
        "    link/ether 08:00:27:aa:bb:cc brd ff:ff:ff:ff:ff:ff\n"
        "    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic eth0\n"
        "       valid_lft 86234sec preferred_lft 86234sec\n"
      )
      for index, interface in enumerate(self.extra_network_interfaces, start=3):
        output += (
          f"{index}: {interface.name}: <BROADCAST,MULTICAST,{interface.state},LOWER_UP> mtu 1500 qdisc noqueue state {interface.state} group default qlen 1000\n"
          f"    link/ether {interface.mac_address} brd ff:ff:ff:ff:ff:ff\n"
          f"    inet {interface.ipv4_address} scope global {interface.name}\n"
          "       valid_lft forever preferred_lft forever\n"
        )
      return output

    if subject in ("route", "r"):
      return (
        "default via 10.0.2.2 dev eth0 proto dhcp metric 100\n"
        "10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100\n"
      )

    if subject in ("link", "l"):
      output = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
        "    link/ether 08:00:27:aa:bb:cc brd ff:ff:ff:ff:ff:ff\n"
      )
      for index, interface in enumerate(self.extra_network_interfaces, start=3):
        output += (
          f"{index}: {interface.name}: <BROADCAST,MULTICAST,{interface.state},LOWER_UP> mtu 1500 qdisc noqueue state {interface.state} mode DEFAULT group default qlen 1000\n"
          f"    link/ether {interface.mac_address} brd ff:ff:ff:ff:ff:ff\n"
        )
      return output

    return f"Object \"{subject}\" is unknown, try \"ip help\".\n"

  def do_df(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    human_readable = any(a.startswith('-') and 'h' in a for a in args)

    if human_readable:
      rows = [
        ("/dev/sda1", "20G", "7.3G", "12G", "39%", "/"),
        ("tmpfs", "1.9G", "0", "1.9G", "0%", "/dev/shm"),
      ]
    else:
      rows = [
        ("/dev/sda1", "20511312", "7654321", "11856991", "39%", "/"),
        ("tmpfs", "1992000", "0", "1992000", "0%", "/dev/shm"),
      ]

    if clean_args:
      rows = [row for row in rows if row[5] in clean_args] or rows

    header = f"{'Filesystem':<12}{'Size' if human_readable else '1K-blocks':<12}{'Used':<12}{'Avail':<12}{'Use%':<8}Mounted on\n"
    lines = [header.rstrip("\n")]
    for filesystem, size, used, avail, use_pct, mount_point in rows:
      lines.append(f"{filesystem:<12}{size:<12}{used:<12}{avail:<12}{use_pct:<8}{mount_point}")
    return "\n".join(lines) + "\n"

  def do_mount(self, args: list):
    if args:
      return ""

    return (
      "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
      "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
      "/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"
      "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
    )

  def do_systemctl(self, args: list):
    if "--failed" in args or "--state=failed" in args:
      failed_units = [u for u in self.systemd_units if u.active_state == "failed"]
      if not failed_units:
        return "0 loaded units listed.\n"
      header = f"{'UNIT':<38}{'LOAD':<10}{'ACTIVE':<10}{'SUB':<10}DESCRIPTION\n"
      rows = "".join(
        f"{u.name:<38}{u.load_state:<10}{u.active_state:<10}{u.sub_state:<10}{u.description}\n"
        for u in failed_units
      )
      return header + rows + f"\n{len(failed_units)} loaded units listed.\n"

    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: systemctl [OPTIONS...] COMMAND ...\n"

    action = clean_args[0]
    unit = clean_args[1] if len(clean_args) > 1 else None

    if action in ("list-units", "list-unit-files"):
      header = f"{'UNIT':<38}{'LOAD':<10}{'ACTIVE':<10}{'SUB':<10}DESCRIPTION\n"
      rows = "".join(
        f"{u.name:<38}{u.load_state:<10}{u.active_state:<10}{u.sub_state:<10}{u.description}\n"
        for u in self.systemd_units
      )
      return header + rows

    if action in ("start", "restart", "enable", "disable", "daemon-reload", "link"):
      return ""

    if action == "status":
      if unit is None:
        return "Usage: systemctl status UNIT\n"
      matching_unit = next((u for u in self.systemd_units if u.name == unit or u.name == f"{unit}.service"), None)
      if matching_unit is None:
        display_unit = unit if unit.endswith(".service") else f"{unit}.service"
        return f"Unit {display_unit} could not be found.\n"
      symbol = "●" if matching_unit.active_state == "active" else "×"
      return (
        f"{symbol} {matching_unit.name} - {matching_unit.description}\n"
        f"     Loaded: {matching_unit.load_state} (/lib/systemd/system/{matching_unit.name}; enabled)\n"
        f"     Active: {matching_unit.active_state} ({matching_unit.sub_state})\n"
      )

    return f"Unknown operation {action}.\n"

  def do_last(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    username_filter = clean_args[0] if clean_args else None

    lines = []
    for event in reversed(self.login_events):
      if username_filter and event.username != username_filter:
        continue
      status = "" if event.success else " gone - no logout"
      lines.append(f"{event.username:<8} pts/0    {event.source_ip:<16} {event.timestamp_label}{status}")

    lines.append(
      f"{self.current_user:<8} pts/0    192.168.1.100   {datetime.now().strftime('%a %b %d %H:%M')}   still logged in"
    )
    lines.append("")
    lines.append(f"wtmp begins {(datetime.now() - timedelta(days=30)).strftime('%a %b %d %H:%M:%S %Y')}")
    return "\n".join(lines) + "\n"

  def do_journalctl(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    unit_filter = None
    for index, arg in enumerate(args):
      if arg == "-u" and index + 1 < len(args):
        unit_filter = args[index + 1]

    unit_label = unit_filter or (clean_args[0] if clean_args else "system")
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    lines = [f"-- Journal begins at {timestamp}, ends at {timestamp}. --"]

    if unit_label in ("sshd", "ssh.service", "auth", "system"):
      for event in self.login_events:
        verdict = "Accepted" if event.success else "Failed"
        lines.append(
          f"{event.timestamp_label} ubuntu sshd[{randint(1000, 9999)}]: "
          f"{verdict} {event.method} for {event.username} from {event.source_ip} port {randint(30000, 65000)} ssh2"
        )

    lines.append(f"{timestamp} ubuntu systemd[1]: Started {unit_label}.")
    return "\n".join(lines) + "\n"

  def do_lsof(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    is_network_query = "-i" in args
    is_unix_query = "-U" in args

    if is_network_query:
      header = f"{'COMMAND':<10}{'PID':<8}{'USER':<10}{'FD':<6}{'TYPE':<7}{'NODE':<8}NAME\n"
      lines = [header.rstrip("\n")]
      for conn in self.network_connections:
        lines.append(
          f"{'sshd':<10}{'1':<8}{'root':<10}{'3u':<6}{'IPv4':<7}{'0':<8}{conn.local_address}->{conn.remote_address} ({conn.state})"
        )
      return "\n".join(lines) + "\n"

    if is_unix_query:
      header = f"{'COMMAND':<10}{'PID':<8}{'USER':<10}{'FD':<6}{'TYPE':<7}{'NODE':<8}NAME\n"
      lines = [header.rstrip("\n")]
      for socket_info in self.unix_sockets:
        lines.append(
          f"{socket_info.process_command.split('/')[-1][:9]:<10}{randint(1000, 2000):<8}{'root':<10}{'5u':<6}{'unix':<7}{'0':<8}{socket_info.path}"
        )
      return "\n".join(lines) + "\n"

    if clean_args:
      file_path = clean_args[0]
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      if self.vfs.get_node(virtual_path) is None:
        return ""
      return f"{'COMMAND':<10}{'PID':<8}{'USER':<10}{'FD':<6}{'TYPE':<7}{'DEVICE':<10}NAME\nbash      {randint(1000, 2000):<8}{self.current_user:<10}3r    REG      8,1       {file_path}\n"

    header = f"{'COMMAND':<10}{'PID':<8}{'USER':<10}{'FD':<6}{'TYPE':<7}{'DEVICE':<10}NAME\n"
    return header

  def do_top(self, args: list):
    header = (
      f"top - {datetime.now().strftime('%H:%M:%S')} up 1 day,  2:14,  1 user,  load average: 0.15, 0.10, 0.05\n"
      f"Tasks: {len(self.process_list):>3} total,   1 running, {len(self.process_list) - 1:>3} sleeping,   0 stopped,   0 zombie\n"
      "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa\n"
      "MiB Mem :   3928.0 total,   1802.4 free,    612.1 used,   1513.5 buff/cache\n"
      "MiB Swap:      0.0 total,      0.0 free,      0.0 used.   3102.7 avail Mem\n\n"
      f"{'PID':>7} {'USER':<9}{'PR':>3} {'NI':>3} {'VIRT':>8} {'RES':>7} {'SHR':>7} S {'%CPU':>6} {'%MEM':>6}  {'TIME+':>9} COMMAND\n"
    )
    rows = []
    for process in self.process_list:
      rows.append(
        f"{process.pid:>7} {process.user:<9}{'20':>3} {'0':>3} {process.vsz:>8} {process.rss:>7} {'0':>7} "
        f"{process.stat[:1]:<1} {process.cpu_usage:>6.1f} {process.memory_usage:>6.1f}  {process.time:>9} {process.command}"
      )
    return header + "\n".join(rows) + "\n"


  def _read_lines_for(self, clean_args: list[str], stdin: str | None, usage: str) -> tuple[list[str] | None, str]:
    if not clean_args:
      if stdin is None:
        return None, usage
      return stdin.splitlines(), ""

    file_path = clean_args[0]
    try:
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      return content.splitlines(), ""
    except Exception:
      return None, f"{file_path}: No such file or directory\n"

  def do_sort(self, args: list, stdin: str | None = None):
    try:
      optlist, clean_args = getopt.getopt(args, "run")
    except Exception:
      return "sort: invalid option\n"

    lines, error = self._read_lines_for(clean_args, stdin, "")
    if lines is None:
      return error if error else ""

    numeric = any(opt == "-n" for opt, _ in optlist)
    reverse = any(opt == "-r" for opt, _ in optlist)
    unique = any(opt == "-u" for opt, _ in optlist)

    if numeric:
      def sort_key(line: str):
        match = re.match(r'^\s*-?\d+(\.\d+)?', line)
        return float(match.group(0)) if match else 0.0
      lines = sorted(lines, key=sort_key, reverse=reverse)
    else:
      lines = sorted(lines, reverse=reverse)

    if unique:
      deduped: list[str] = []
      for line in lines:
        if not deduped or deduped[-1] != line:
          deduped.append(line)
      lines = deduped

    return "\n".join(lines) + "\n" if lines else ""

  def _hash_command(self, algorithm: str, args: list, stdin: str | None = None) -> str:
    clean_args = [a for a in args if not a.startswith('-')]
    hasher_name = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}[algorithm]

    if not clean_args:
      if stdin is None:
        return ""
      digest = hashlib.new(hasher_name, stdin.encode('utf-8')).hexdigest()
      return f"{digest}  -\n"

    output = ""
    for file_path in clean_args:
      try:
        virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
        content = self.vfs.file_contents(virtual_path)
        digest = hashlib.new(hasher_name, content).hexdigest()
        output += f"{digest}  {file_path}\n"
      except Exception:
        output += f"{algorithm}sum: {file_path}: No such file or directory\n"
    return output

  def do_md5sum(self, args: list, stdin: str | None = None):
    return self._hash_command("md5", args, stdin)

  def do_sha1sum(self, args: list, stdin: str | None = None):
    return self._hash_command("sha1", args, stdin)

  def do_sha256sum(self, args: list, stdin: str | None = None):
    return self._hash_command("sha256", args, stdin)

  def do_stat(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: stat FILE...\n"

    output = ""
    for file_path in clean_args:
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      node = self.vfs.get_node(virtual_path)
      if node is None:
        output += f"stat: cannot statx '{file_path}': No such file or directory\n"
        continue
      file_type = "directory" if isinstance(node, FSDirectory) else "regular file"
      size = len(node.content.encode('latin-1')) if isinstance(node, FSFile) else node.size
      output += (
        f"  File: {file_path}\n"
        f"  Size: {size:<10}\tBlocks: {(size // 512) + 1:<10} IO Block: 4096   {file_type}\n"
        f"Access: ({node.permissions})  Uid: ({node.uid}/{self.current_user})   Gid: ({node.gid}/{self.current_user})\n"
        f"Modify: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f000 +0000')}\n"
      )
    return output

  def do_file(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: file FILE...\n"

    output = ""
    for file_path in clean_args:
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      node = self.vfs.get_node(virtual_path)
      if node is None:
        output += f"{file_path}: cannot open (No such file or directory)\n"
        continue
      if isinstance(node, FSDirectory):
        output += f"{file_path}: directory\n"
        continue
      try:
        content = self.vfs.file_contents(virtual_path)
      except Exception:
        content = b""
      if content.startswith(b"#!"):
        interpreter = content.split(b"\n")[0][2:].decode('utf-8', errors='replace').strip()
        output += f"{file_path}: {interpreter} script, ASCII text executable\n"
      elif content.startswith(b"\x7fELF"):
        output += f"{file_path}: ELF 64-bit LSB executable, x86-64\n"
      elif not content:
        output += f"{file_path}: empty\n"
      else:
        output += f"{file_path}: ASCII text\n"
    return output

  def do_basename(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: basename NAME [SUFFIX]\n"
    name = posixpath.basename(clean_args[0].rstrip("/"))
    if len(clean_args) > 1 and name.endswith(clean_args[1]):
      name = name[: -len(clean_args[1])]
    return name + "\n"

  def do_dirname(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: dirname NAME\n"
    result = posixpath.dirname(clean_args[0].rstrip("/"))
    return (result or ".") + "\n"

  def do_realpath(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: realpath FILE\n"
    return self.vfs.resolve_path(clean_args[0], self.vfs.cwd_path) + "\n"

  def do_readlink(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "f")
    except Exception:
      return "Usage: readlink [-f] FILE\n"
    if not clean_args:
      return "Usage: readlink [-f] FILE\n"
    if any(opt == "-f" for opt, _ in optlist):
      return self.vfs.resolve_path(clean_args[0], self.vfs.cwd_path) + "\n"
    return ""

  def do_dd(self, args: list):
    ddargs: dict[str, str] = {}
    for arg in args:
      if "=" not in arg:
        continue
      operand, value = arg.split("=", 1)
      ddargs[operand] = value

    if "if" in ddargs:
      source_path = self.vfs.resolve_path(ddargs["if"], self.vfs.cwd_path)
      source_node = self.vfs.get_node(source_path)
      content = source_node.content if isinstance(source_node, FSFile) else ""
    else:
      content = ""

    if "of" in ddargs:
      dest_path = self.vfs.resolve_path(ddargs["of"], self.vfs.cwd_path)
      if self.vfs.get_node(dest_path) is None:
        realfile = os.path.join("honeyfs", dest_path.lstrip("/"))
        self.vfs.mkfile_p(dest_path, uid=0, gid=0, size=len(content), mode="rw-r--r--", realfile=realfile)
      self.vfs.override_file_contents(dest_path, content.encode('latin-1'))
      self.vfs.override_file_metadata(dest_path, {"size": len(content)})

    return "0+0 records in\n0+0 records out\n0 bytes copied, 0.0 s, 0.0 B/s\n"

  def do_set(self, args: list):
    return ""

  def do_tee(self, args: list, stdin: str | None = None):
    try:
      optlist, clean_args = getopt.getopt(args, "a", ["append"])
    except Exception:
      return "Usage: tee [OPTION]... [FILE]...\n"

    is_append = any(opt in ("-a", "--append") for opt, _ in optlist)
    content = stdin or ""

    for file_arg in clean_args:
      virtual_path = self.vfs.resolve_path(file_arg, self.vfs.cwd_path)
      if self.vfs.get_node(virtual_path) is None:
        realfile = os.path.join("honeyfs", virtual_path.lstrip("/"))
        self.vfs.mkfile_p(virtual_path, uid=0, gid=0, size=0, mode="rw-r--r--", realfile=realfile)
      if is_append:
        node = self.vfs.get_node(virtual_path)
        existing = node.content if isinstance(node, FSFile) else ""
        self.vfs.override_file_contents(virtual_path, (existing + content).encode('latin-1'))
      else:
        self.vfs.override_file_contents(virtual_path, content.encode('latin-1'))
      self.vfs.override_file_metadata(virtual_path, {"size": len(content)})

    return content

  def do_cp(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "rRfva", ["recursive", "force", "verbose"])
    except Exception:
      return "cp: invalid option\nTry 'cp --help' for more information.\n"
    if len(clean_args) < 2:
      return "cp: missing file operand\nTry 'cp --help' for more information.\n"

    *sources, destination = clean_args
    dest_path = self.vfs.resolve_path(destination, self.vfs.cwd_path)
    dest_node = self.vfs.get_node(dest_path)
    dest_is_dir = isinstance(dest_node, FSDirectory)

    if len(sources) > 1 and not dest_is_dir:
      return f"cp: target '{destination}' is not a directory\n"

    output = ""
    for source in sources:
      source_path = self.vfs.resolve_path(source, self.vfs.cwd_path)
      source_node = self.vfs.get_node(source_path)
      if source_node is None:
        output += f"cp: cannot stat '{source}': No such file or directory\n"
        continue
      if isinstance(source_node, FSDirectory):
        output += f"cp: -r not specified; omitting directory '{source}'\n"
        continue

      target_path = (
        posixpath.join(dest_path, source_node.name) if dest_is_dir else dest_path
      )
      if self.vfs.get_node(target_path) is None:
        realfile = os.path.join("honeyfs", target_path.lstrip("/"))
        self.vfs.mkfile_p(
          target_path, uid=source_node.uid, gid=source_node.gid,
          size=source_node.size, mode=source_node.permissions, realfile=realfile,
        )
      self.vfs.override_file_contents(target_path, source_node.content.encode('latin-1'))
    return output

  def do_ln(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "sf")
    except Exception:
      return "Usage: ln [OPTION]... TARGET LINK_NAME\n"
    if len(clean_args) < 2:
      return "Usage: ln [OPTION]... TARGET LINK_NAME\n"

    target, link_name = clean_args[0], clean_args[1]
    target_path = self.vfs.resolve_path(target, self.vfs.cwd_path)
    target_node = self.vfs.get_node(target_path)
    if target_node is None:
      return f"ln: failed to access '{target}': No such file or directory\n"

    link_path = self.vfs.resolve_path(link_name, self.vfs.cwd_path)
    if self.vfs.get_node(link_path) is None:
      is_symbolic = any(opt == "-s" for opt, _ in optlist)
      mode = "lrwxrwxrwx" if is_symbolic else target_node.permissions
      self.vfs.mkfile_p(link_path, uid=target_node.uid, gid=target_node.gid, size=target_node.size, mode=mode)
      if isinstance(target_node, FSFile):
        self.vfs.override_file_contents(link_path, target_node.content.encode('latin-1'))
    return ""

  def do_truncate(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "s:", ["size="])
    except Exception:
      return "Usage: truncate OPTION... FILE...\n"

    size = 0
    for opt, opt_value in optlist:
      if opt in ("-s", "--size"):
        try:
          size = int(re.sub(r'[^0-9-]', '', opt_value) or 0)
        except ValueError:
          size = 0

    if not clean_args:
      return "Usage: truncate OPTION... FILE...\n"

    for file_path in clean_args:
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      if self.vfs.get_node(virtual_path) is None:
        self.vfs.mkfile_p(virtual_path, uid=0, gid=0, size=size, mode="-rw-r--r--")
      node = self.vfs.get_node(virtual_path)
      if isinstance(node, FSFile):
        current = node.content
        node.content = current[:size].ljust(size, "\0") if size > len(current) else current[:size]
        node.size = size
    return ""

  def do_xxd(self, args: list, stdin: str | None = None):
    clean_args = [a for a in args if not a.startswith('-')]
    lines, error = self._read_lines_for(clean_args, stdin, "")
    if lines is None:
      return error

    raw = ("\n".join(lines)).encode('utf-8')
    output_lines = []
    for offset in range(0, len(raw), 16):
      chunk = raw[offset:offset + 16]
      hex_part = " ".join(f"{chunk[i]:02x}{chunk[i + 1]:02x}" if i + 1 < len(chunk) else f"{chunk[i]:02x}" for i in range(0, len(chunk), 2))
      ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
      output_lines.append(f"{offset:08x}: {hex_part:<39} {ascii_part}")
    return "\n".join(output_lines) + "\n" if output_lines else ""

  def do_strings(self, args: list, stdin: str | None = None):
    clean_args = [a for a in args if not a.startswith('-')]

    if not clean_args:
      if stdin is None:
        return "Usage: strings FILE\n"
      content = stdin.encode('utf-8')
    else:
      file_path = clean_args[0]
      try:
        virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
        content = self.vfs.file_contents(virtual_path)
      except Exception:
        return f"strings: '{file_path}': No such file or directory\n"

    printable_runs = re.findall(rb"[\x20-\x7e]{4,}", content)
    return "\n".join(run.decode('ascii') for run in printable_runs) + "\n" if printable_runs else ""

  def _apply_sed_script(self, script: str, lines: list[str]) -> list[str]:
    substitution_match = re.match(r'^s(.)(.*)\1(.*)\1(g?)$', script)
    if substitution_match:
      _, pattern, replacement, flags = substitution_match.groups()
      count = 0 if "g" in flags else 1
      try:
        return [re.sub(pattern, replacement.replace('\\/', '/'), line, count=count) for line in lines]
      except re.error:
        return lines

    deletion_match = re.match(r'^(.)(.*)\1d$', script)
    if deletion_match:
      _, pattern = deletion_match.groups()
      try:
        return [line for line in lines if not re.search(pattern, line)]
      except re.error:
        return lines

    return lines

  def do_sed(self, args: list, stdin: str | None = None):
    try:
      optlist, remaining_args = getopt.getopt(args, "e:in", ["expression="])
    except Exception:
      return "Usage: sed [OPTION]... {script} [input-file]...\n"

    in_place = any(opt == "-i" for opt, _ in optlist)
    scripts = [value for opt, value in optlist if opt in ("-e", "--expression")]

    positional = list(remaining_args)
    if not scripts:
      if not positional:
        return "Usage: sed [OPTION]... {script} [input-file]...\n"
      scripts = [positional.pop(0)]

    if positional:
      file_path = positional[0]
      try:
        virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
        lines = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace').splitlines()
      except Exception:
        return f"sed: can't read {file_path}: No such file or directory\n"
    elif stdin is not None:
      virtual_path = None
      lines = stdin.splitlines()
    else:
      return "Usage: sed [OPTION]... {script} [input-file]...\n"

    for script in scripts:
      lines = self._apply_sed_script(script, lines)

    result = "\n".join(lines) + ("\n" if lines else "")

    if in_place and positional and virtual_path is not None:
      self.vfs.override_file_contents(virtual_path, result.encode('utf-8'))
      return ""

    return result

  def _fake_pem_block(self, label: str) -> str:
    body = base64.b64encode(secrets.token_bytes(512)).decode('ascii')
    wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"

  def do_openssl(self, args: list, stdin: str | None = None):
    if not args:
      return "openssl:Error: no command specified\n"

    subcommand = args[0]
    sub_args = args[1:]

    if subcommand == "passwd":
      salt = None
      remaining = []
      index = 0
      while index < len(sub_args):
        value = sub_args[index]
        if value == "-salt" and index + 1 < len(sub_args):
          salt = sub_args[index + 1]
          index += 2
          continue
        if not value.startswith('-'):
          remaining.append(value)
        index += 1

      password = remaining[0] if remaining else (stdin or "")
      salt = salt or secrets.token_hex(4)
      digest = hashlib.sha512(f"{salt}{password}".encode()).hexdigest()
      return f"$6${salt}${digest}\n"

    if subcommand == "enc":
      is_decrypt = "-d" in sub_args
      in_path = None
      out_path = None
      for index, value in enumerate(sub_args):
        if value == "-in" and index + 1 < len(sub_args):
          in_path = sub_args[index + 1]
        elif value == "-out" and index + 1 < len(sub_args):
          out_path = sub_args[index + 1]

      if in_path:
        try:
          virtual_path = self.vfs.resolve_path(in_path, self.vfs.cwd_path)
          data = self.vfs.file_contents(virtual_path)
        except Exception:
          return f"openssl: unable to load key/input file {in_path}\n"
      elif stdin is not None:
        data = stdin.encode('utf-8')
      else:
        return "openssl:Error: no input\n"

      transformed = base64.b64decode(data) if is_decrypt else base64.b64encode(data)

      if out_path:
        virtual_out = self.vfs.resolve_path(out_path, self.vfs.cwd_path)
        if self.vfs.get_node(virtual_out) is None:
          self.vfs.mkfile_p(virtual_out, uid=0, gid=0, size=len(transformed), mode="-rw-------")
        self.vfs.override_file_contents(virtual_out, transformed)
        return ""
      return transformed.decode('utf-8', errors='replace') + "\n"

    if subcommand in ("genrsa", "genpkey"):
      out_path = None
      for index, value in enumerate(sub_args):
        if value == "-out" and index + 1 < len(sub_args):
          out_path = sub_args[index + 1]
      pem = self._fake_pem_block("RSA PRIVATE KEY")
      if out_path:
        virtual_path = self.vfs.resolve_path(out_path, self.vfs.cwd_path)
        self.vfs.mkfile_p(virtual_path, uid=0, gid=0, size=len(pem), mode="-rw-------")
        self.vfs.override_file_contents(virtual_path, pem.encode('utf-8'))
        return ""
      return pem

    if subcommand in ("req", "x509"):
      out_path = None
      for index, value in enumerate(sub_args):
        if value in ("-out", "-keyout") and index + 1 < len(sub_args):
          out_path = sub_args[index + 1]
      pem = self._fake_pem_block("CERTIFICATE")
      if out_path:
        virtual_path = self.vfs.resolve_path(out_path, self.vfs.cwd_path)
        self.vfs.mkfile_p(virtual_path, uid=0, gid=0, size=len(pem), mode="-rw-r--r--")
        self.vfs.override_file_contents(virtual_path, pem.encode('utf-8'))
        return ""
      return pem

    if subcommand == "dgst":
      algorithm = "sha256"
      for flag in ("-md5", "-sha1", "-sha256", "-sha512"):
        if flag in sub_args:
          algorithm = flag[1:]
      file_args = [a for a in sub_args if not a.startswith('-')]
      if file_args:
        try:
          virtual_path = self.vfs.resolve_path(file_args[0], self.vfs.cwd_path)
          data = self.vfs.file_contents(virtual_path)
        except Exception:
          return f"openssl: unable to load {file_args[0]}\n"
        digest = hashlib.new(algorithm, data).hexdigest()
        return f"{algorithm.upper()}({file_args[0]})= {digest}\n"
      if stdin is not None:
        digest = hashlib.new(algorithm, stdin.encode('utf-8')).hexdigest()
        return f"{digest}\n"
      return ""

    if subcommand == "version":
      return "OpenSSL 3.0.2 15 Mar 2022\n"

    return f"openssl:Error: '{subcommand}' is an invalid command.\n"


  def do_usermod(self, args: list):
    try:
      optlist, remaining = getopt.getopt(args, "aG:d:s:u:g:")
    except Exception:
      return "Usage: usermod [options] LOGIN\n"

    if not remaining:
      return "Usage: usermod [options] LOGIN\n"

    username = remaining[-1]
    for opt, opt_value in optlist:
      if opt == "-u":
        with contextlib.suppress(ValueError):
          self._KNOWN_UIDS[username] = int(opt_value)
      elif opt == "-g":
        gid = self._KNOWN_GIDS.get(opt_value, self._resolve_owner_spec(f":{opt_value}")[1])
        if gid is not None:
          self._KNOWN_GIDS[username] = gid
    return ""

  def do_groupadd(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: groupadd [options] GROUP\n"
    group = clean_args[0]
    if group in self._KNOWN_GIDS:
      return f"groupadd: group '{group}' already exists\n"
    self._KNOWN_GIDS[group] = 1000 + (hash(group) % 8999)
    return ""

  def do_groupdel(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: groupdel GROUP\n"
    group = clean_args[0]
    if group not in self._KNOWN_GIDS:
      return f"groupdel: group '{group}' does not exist\n"
    del self._KNOWN_GIDS[group]
    return ""


  def do_dpkg(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    is_list = "-l" in args or "--list" in args

    if is_list:
      packages = self.installed_packages
      if clean_args:
        packages = [p for p in packages if any(c in p.name for c in clean_args)] or packages
      header = "Desired=Unknown/Install/Remove/Purge/Hold\n| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n||/ Name           Version               Architecture Description\n+++-==============-=====================-============-=========================\n"
      rows = "".join(f"ii  {p.name:<15}{p.version:<22}{p.architecture:<13}{p.description}\n" for p in packages)
      return header + rows

    if "-s" in args and clean_args:
      package_name = clean_args[-1]
      package = next((p for p in self.installed_packages if p.name == package_name), None)
      if package is None:
        return f"dpkg-query: package '{package_name}' is not installed\n"
      return f"Package: {package.name}\nStatus: install ok installed\nVersion: {package.version}\nArchitecture: {package.architecture}\nDescription: {package.description}\n"

    return "Usage: dpkg [options] action\n"

  def do_lsblk(self, args: list):
    return (
      "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
      "sda      8:0    0   20G  0 disk\n"
      "└─sda1   8:1    0   20G  0 part /\n"
    )

  def do_lsmod(self, args: list):
    return (
      "Module                  Size  Used by\n"
      "nf_conntrack          172032  1\n"
      "ip_tables              32768  0\n"
      "x_tables               45056  1 ip_tables\n"
    )

  def do_dmesg(self, args: list):
    lines = [
      "[    0.000000] Linux version 5.15.0-179-generic",
      "[    0.512340] Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-179-generic root=/dev/sda1",
      "[    2.104521] systemd[1]: Started Network Manager.",
      "[    3.881233] sshd[842]: Server listening on 0.0.0.0 port 22.",
    ]
    return "\n".join(lines) + "\n"

  def do_vmstat(self, args: list):
    return (
      "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n"
      " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n"
      f" {min(len(self.process_list), 9)}  0      0 1802400  61200 1513500    0    0     2     8   45   90  1  1 98  0  0\n"
    )

  def do_ldd(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: ldd FILE...\n"
    return (
      "\tlinux-vdso.so.1 (0x00007ffe1c9dc000)\n"
      "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9a1e400000)\n"
      "\t/lib64/ld-linux-x86-64.so.2 (0x00007f9a1e600000)\n"
    )

  def do_visudo(self, args: list):
    if "-c" in args:
      return "/etc/sudoers: parsed OK\n"
    return "visudo: /etc/sudoers unchanged\n"

  def do_at(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "at> \n"
    job_id = randint(1, 99)
    run_time = datetime.now() + timedelta(minutes=1)
    return f"job {job_id} at {run_time.strftime('%a %b %d %H:%M:%S %Y')}\n"


  def do_gzip(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "kdcf")
    except Exception:
      return "Usage: gzip [OPTION]... FILE...\n"
    if not clean_args:
      return "Usage: gzip [OPTION]... FILE...\n"

    keep_original = any(opt == "-k" for opt, _ in optlist)
    decompress = any(opt == "-d" for opt, _ in optlist)

    output = ""
    for file_path in clean_args:
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      try:
        content = self.vfs.file_contents(virtual_path)
      except Exception:
        output += f"gzip: {file_path}: No such file or directory\n"
        continue

      if decompress:
        try:
          new_content = gzip_module.decompress(content)
        except Exception:
          output += f"gzip: {file_path}: not in gzip format\n"
          continue
        new_path = virtual_path[:-3] if virtual_path.endswith(".gz") else virtual_path
      else:
        new_content = gzip_module.compress(content)
        new_path = virtual_path + ".gz"

      self.vfs.mkfile_p(new_path, uid=0, gid=0, size=len(new_content), mode="-rw-r--r--")
      self.vfs.override_file_contents(new_path, new_content)
      if not keep_original:
        self.vfs.delete_node(virtual_path)
    return output

  def do_bzip2(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "kdcf")
    except Exception:
      return "Usage: bzip2 [OPTION]... FILE...\n"
    if not clean_args:
      return "Usage: bzip2 [OPTION]... FILE...\n"

    keep_original = any(opt == "-k" for opt, _ in optlist)
    decompress = any(opt == "-d" for opt, _ in optlist)

    output = ""
    for file_path in clean_args:
      virtual_path = self.vfs.resolve_path(file_path, self.vfs.cwd_path)
      try:
        content = self.vfs.file_contents(virtual_path)
      except Exception:
        output += f"bzip2: {file_path}: No such file or directory\n"
        continue

      if decompress:
        try:
          new_content = bz2.decompress(content)
        except Exception:
          output += f"bzip2: {file_path}: not a bzip2 file\n"
          continue
        new_path = virtual_path[:-4] if virtual_path.endswith(".bz2") else virtual_path
      else:
        new_content = bz2.compress(content)
        new_path = virtual_path + ".bz2"

      self.vfs.mkfile_p(new_path, uid=0, gid=0, size=len(new_content), mode="-rw-r--r--")
      self.vfs.override_file_contents(new_path, new_content)
      if not keep_original:
        self.vfs.delete_node(virtual_path)
    return output

  def do_zip(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if len(clean_args) < 2:
      return "zip error: Nothing to do!\n"

    archive_name = clean_args[0]
    if not archive_name.endswith(".zip"):
      archive_name += ".zip"
    member_paths = clean_args[1:]

    buffer = io.BytesIO()
    added = []
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
      for member in member_paths:
        virtual_path = self.vfs.resolve_path(member, self.vfs.cwd_path)
        try:
          content = self.vfs.file_contents(virtual_path)
        except Exception:
          continue
        archive.writestr(posixpath.basename(member), content)
        added.append(member)

    if not added:
      return "zip error: Nothing to do!\n"

    archive_path = self.vfs.resolve_path(archive_name, self.vfs.cwd_path)
    archive_bytes = buffer.getvalue()
    self.vfs.mkfile_p(archive_path, uid=0, gid=0, size=len(archive_bytes), mode="-rw-r--r--")
    self.vfs.override_file_contents(archive_path, archive_bytes)

    lines = [f"  adding: {member} (deflated)" for member in added]
    return f"  adding: {archive_name}\n" + "\n".join(lines) + "\n"


  def do_ufw(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    action = clean_args[0] if clean_args else "status"

    if action == "status":
      header = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
      return header + "\n".join(self.firewall_rules) + "\n"
    if action in ("allow", "deny", "reject"):
      target = " ".join(clean_args[1:]) or "Anywhere"
      verb = {"allow": "ALLOW", "deny": "DENY", "reject": "REJECT"}[action]
      self.firewall_rules.append(f"{target:<27}{verb:<12}Anywhere")
      return "Rule added\n"
    if action == "delete":
      return "Rule updated\n"
    if action in ("enable", "disable", "reset"):
      if action == "reset":
        self.firewall_rules = []
      return f"Firewall {action}d\n"
    return f"ERROR: Invalid command '{action}'\n"

  def do_auditctl(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if "-l" in args:
      return "-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n"
    if "-s" in args:
      return "enabled 1\nfailure 1\npid 842\nrate_limit 0\nbacklog_limit 8192\nlost 0\nbacklog 0\n"
    if not clean_args and not args:
      return "No rules\n"
    return ""

  def do_systemd_run(self, args: list):
    clean_args = [a for a in args if not a.startswith('-')]
    if not clean_args:
      return "Usage: systemd-run [OPTIONS...] COMMAND [ARGS...]\n"
    unit_name = f"run-{randint(100000, 999999)}.scope"
    return f"Running as unit: {unit_name}\n"