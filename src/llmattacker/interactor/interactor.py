"""SSH client used by the attacker to send commands and read their output."""

import re
import time

import paramiko
from loguru import logger

_PROMPT_TAIL_RE = re.compile(r"@ubuntu:[^\r\n]*[#$] $")


logger.add("logs/interactor.log", rotation="10 MB")

class Interactor:
  def __init__(self, host: str, port: int, username: str, password: str):
    self.host = host
    self.port = port
    self.username = username
    self.password = password
    self.ssh_client = paramiko.SSHClient()
    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    self.shell: paramiko.Channel | None = None
  
  def connect(self) -> bool:
    try:
      logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
      self.ssh_client.connect(
        hostname=self.host,
        port=self.port,
        username=self.username,
        password=self.password,
        timeout=10
      )
      transport = self.ssh_client.get_transport()
      if transport is not None:
        transport.set_keepalive(15)
      self.shell = self.ssh_client.invoke_shell()

      time.sleep(1)
      if self.shell.recv_ready():
        welcome_message = self.shell.recv(4096).decode('utf-8')
        logger.debug(f"Welcome message from {self.host}: {welcome_message}")

      logger.success(f"Successfully connected to {self.host}")
      return True
    except Exception as e:
      logger.error(f"Failed to connect to {self.host}: {e}")
      return False
  
  def execute_command(self, command: str, wait_time: float = 1.0, max_wait_time: float = 15.0) -> str:
    if not self.shell:
      raise ConnectionError("Not connected to any host.")

    logger.info(f"Executing command on {self.host}: {command}")
    t0 = time.monotonic()

    stale_bytes = 0
    while self.shell.recv_ready():
      stale = self.shell.recv(4096)
      stale_bytes += len(stale)
    if stale_bytes:
      logger.warning(
        f"[timing] Drained {stale_bytes} stale bytes left over from the "
        f"previous command before sending {command!r} -- that command's "
        f"quiet window likely closed before its real response arrived."
      )

    full_command = command + '\n'
    self.shell.send(full_command.encode('utf-8'))
    t_sent = time.monotonic()
    logger.debug(f"[timing] send() took {t_sent - t0:.3f}s for command: {command!r}")

    poll_interval = 0.1
    elapsed = 0.0
    while elapsed < max_wait_time and not self.shell.recv_ready():
      time.sleep(poll_interval)
      elapsed += poll_interval
    t_after_sleep = time.monotonic()

    output = ""
    recv_calls = 0
    while self.shell.recv_ready():
      output += self.shell.recv(4096).decode('utf-8')
      recv_calls += 1

    prompt_deadline = time.monotonic() + max_wait_time
    while not _PROMPT_TAIL_RE.search(output) and time.monotonic() < prompt_deadline:
      if self.shell.recv_ready():
        output += self.shell.recv(4096).decode('utf-8')
        recv_calls += 1
      else:
        time.sleep(poll_interval)

    quiet_deadline = time.monotonic() + 0.5
    while time.monotonic() < quiet_deadline:
      if self.shell.recv_ready():
        output += self.shell.recv(4096).decode('utf-8')
        recv_calls += 1
        quiet_deadline = time.monotonic() + 0.5
      else:
        time.sleep(0.05)

    t_done = time.monotonic()
    logger.debug(
      f"[timing] command={command!r} wait_for_data={t_after_sleep - t_sent:.3f}s "
      f"recv_loop={t_done - t_after_sleep:.3f}s recv_calls={recv_calls} "
      f"output_len={len(output)} total={t_done - t0:.3f}s"
    )
    if recv_calls == 0:
      logger.warning(
        f"[timing] No data was ready after {max_wait_time}s wait for command {command!r} -- "
        f"response may arrive later and be misread as the NEXT command's output, or the "
        f"channel may already be in a bad state."
      )

    clean_output = output.strip()
    return clean_output
  
  def disconnect(self):
    if self.shell:
      self.shell.send(b"exit\n")
      time.sleep(1)
    self.ssh_client.close()
    logger.info(f"Disconnected from {self.host}")
