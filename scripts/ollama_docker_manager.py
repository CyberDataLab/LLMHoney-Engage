"""Starts, stops, and pulls models into the Ollama container used by a campaign."""

import subprocess
import time

from loguru import logger

logger.add("logs/ollama_docker_manager.log", rotation="10 MB")

CONTAINER_NAME = "honeyengage-experiment-ollama"
VOLUME_NAME = "honeyengage-experiment-ollama-models"
OLLAMA_IMAGE = "ollama/ollama"
OLLAMA_PORT = 11434


class OllamaDockerError(RuntimeError):
  pass


def _run(*args: str, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess:
  return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _container_exists() -> bool:
  result = _run("docker", "ps", "-aq", "--filter", f"name=^{CONTAINER_NAME}$", check=False)
  return bool(result.stdout.strip())


def remove_container_and_volume() -> None:
  if _container_exists():
    logger.info(f"Removing existing container '{CONTAINER_NAME}'...")
    _run("docker", "rm", "-f", CONTAINER_NAME, check=False)

  logger.info(f"Removing model-weight volume '{VOLUME_NAME}' (if present)...")
  _run("docker", "volume", "rm", "-f", VOLUME_NAME, check=False)


def start_ollama_container(startup_timeout: float = 60.0) -> None:
  remove_container_and_volume()

  logger.info(f"Starting Ollama container '{CONTAINER_NAME}'...")
  _run(
    "docker", "run", "-d",
    "--name", CONTAINER_NAME,
    "--gpus", "all",
    "--dns", "8.8.8.8",
    "--dns", "8.8.4.4",
    "-p", f"{OLLAMA_PORT}:11434",
    "-v", f"{VOLUME_NAME}:/root/.ollama",
    OLLAMA_IMAGE,
  )

  deadline = time.time() + startup_timeout
  while time.time() < deadline:
    health = _run("docker", "exec", CONTAINER_NAME, "ollama", "list", check=False)
    if health.returncode == 0:
      logger.success("Ollama container is ready.")
      return
    time.sleep(1)

  raise OllamaDockerError(f"Ollama container did not become ready within {startup_timeout}s.")


def pull_model(model_name: str, timeout: float = 1800.0, attempts: int = 5) -> None:
  last_error = ""
  for attempt in range(1, attempts + 1):
    logger.info(f"Pulling model '{model_name}' (attempt {attempt}/{attempts}, this may take a while)...")
    result = _run("docker", "exec", CONTAINER_NAME, "ollama", "pull", model_name, check=False, timeout=timeout)
    if result.returncode == 0:
      logger.success(f"Model '{model_name}' pulled successfully.")
      return
    last_error = (result.stderr or "").strip()
    if attempt < attempts:
      delay = min(60 * attempt, 300)
      logger.warning(
        f"Pull of '{model_name}' failed (attempt {attempt}/{attempts}); retrying in {delay}s. Error: {last_error[-200:]}"
      )
      time.sleep(delay)
  raise OllamaDockerError(f"Failed to pull model '{model_name}' after {attempts} attempts: {last_error}")


def remove_model(model_name: str) -> None:
  logger.info(f"Removing model '{model_name}' to free disk space...")
  _run("docker", "exec", CONTAINER_NAME, "ollama", "rm", model_name, check=False)


class ManagedModel:

  def __init__(self, model_name: str, pull_timeout: float = 1800.0):
    self.model_name = model_name
    self.pull_timeout = pull_timeout

  def __enter__(self) -> str:
    pull_model(self.model_name, timeout=self.pull_timeout)
    return self.model_name

  def __exit__(self, exc_type, exc_value, traceback) -> None:
    remove_model(self.model_name)
