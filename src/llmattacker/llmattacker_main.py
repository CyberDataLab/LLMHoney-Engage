"""Entry point of the LLMAttacker agent."""

import os

from dotenv import load_dotenv

from src.llmattacker.attack_engine.attack_engine import AttackEngine
from src.llmattacker.interactor.interactor import Interactor

load_dotenv()

if __name__ == "__main__":
  interactor = Interactor(
    host="127.0.0.1",
    port=2222,
    username=os.getenv("LLMATTACKER_USER", "root"),
    password=os.getenv("LLMATTACKER_PASS", "root")
  )

  attack_engine = AttackEngine(
    atomics_path=os.path.join("src", "llmattacker", "atomics"),
    interactor=interactor,
    enable_metrics=os.getenv("ENABLE_METRICS", "false").lower() == "true",
    metrics_file="attack_metrics.jsonl",
  )

  session_id = os.getenv("SESSION_ID", "default_session")

  attack_engine.run_simulation(session_id=session_id)