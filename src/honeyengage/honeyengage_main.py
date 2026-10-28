"""Entry point of the HoneyEngage honeypot: loads the configuration and starts the SSH sensor."""

import faulthandler
import os
import signal

from dotenv import load_dotenv
from loguru import logger

from src.honeyengage.sensor.sensor import start_sensor

logger.add("logs/honeyengage_main.log", rotation="10 MB")

def _install_thread_dump_handler():
  dump_path = "logs/honeyengage_thread_dump.log"

  def handler(signum, frame):
    with open(dump_path, "a", encoding="utf-8") as f:
      f.write(f"\n=== Thread dump (signal {signum}) ===\n")
      faulthandler.dump_traceback(file=f, all_threads=True)

  signal.signal(signal.SIGUSR1, handler)
  logger.info(f"Thread dump handler installed (kill -USR1 {os.getpid()} -> {dump_path})")

def main():

  load_dotenv()
  _install_thread_dump_handler()
  logger.info("======================================")
  logger.info("Starting HoneyEngage v1.0...")
  logger.info("======================================")
  
  try:
    port = os.getenv("HONEYENGAGE_PORT", "2222")
    start_sensor(host="0.0.0.0", port=int(port))
  
  except KeyboardInterrupt:
    logger.warning("Shutting down HoneyEngage...")
  except Exception as e:
    logger.critical(f"An error occurred: {e}")
  finally:
    logger.info("HoneyEngage has been stopped.")

if __name__ == "__main__":
  main()