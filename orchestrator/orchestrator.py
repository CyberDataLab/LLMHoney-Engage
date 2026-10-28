"""Runs one defender-versus-attacker session: starts the honeypot, launches the attacker against it over SSH, and waits for both to finish."""

import os
import socket
import subprocess
import sys
import time

from loguru import logger

logger.add("logs/orchestrator.log")

def check_port_availability(port: int, host: str = 'localhost', timeout: float = 5.0) -> bool:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    return result != 0

def wait_for_port(port: int, host: str = 'localhost', timeout: float = 60.0) -> bool:
  start_time = time.time()
  while True:
    try:
      with socket.create_connection((host, port), timeout=1.0):
        return True
    except OSError:
      time.sleep(0.5)
      if time.time() - start_time > timeout:
        return False

def run_single_session(session_id: str, honeyengage_env: dict, llmattacker_env: dict, data_dir: str = "data", max_wait: float = 300) -> bool:
  if not check_port_availability(2222):
    logger.error("Port 2222 is already in use. Please ensure that no other instance of HoneyEngage is running.")
    return False

  honeyengage_process = subprocess.Popen(
    [sys.executable, "-m", "src.honeyengage.honeyengage_main"],
    env=honeyengage_env,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )

  if not wait_for_port(port=2222, timeout=60.0):
    logger.error(f"¡Timeout! HoneyEngage didn't start in time for session {session_id}.")
    honeyengage_process.terminate()
    return False

  time.sleep(1)
  logger.info("-> Honeypot (HoneyEngage) started.")

  logger.info(f"-> Starting attack simulation for session {session_id}...")
  subprocess.run(
    [sys.executable, "-m", "src.llmattacker.llmattacker_main"],
    env=llmattacker_env,
  )

  logger.info("-> Waiting for Honeypot to finish processing...")
  data_file = os.path.join(data_dir, f"{session_id}.json")
  wait_time = 0.0
  while not os.path.exists(data_file) and wait_time < max_wait:
    time.sleep(1)
    wait_time += 1

  succeeded = os.path.exists(data_file)
  if not succeeded:
    logger.error(f"Session {session_id} produced no data file after {max_wait}s.")

  logger.info("-> Turning off Honeypot and cleaning up...")
  honeyengage_process.terminate()
  try:
    honeyengage_process.wait(timeout=5)
  except subprocess.TimeoutExpired:
    honeyengage_process.kill()

  return succeeded
