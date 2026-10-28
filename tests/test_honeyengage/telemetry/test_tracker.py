import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from src.honeyengage.telemetry.models import InteractionInfo, MitreMapping, NetworkInfo, Session
from src.honeyengage.telemetry.tracker import SessionTracker

session_id = f"session_{uuid.uuid4().hex}_192.168.1.50"
source_ip = "192.168.1.50"
source_port = 12345
client_version = "OpenSSH_8.0"
dummy_client = "dummy-client"
engage_parser = MagicMock()
engage_mapper = MagicMock()

class TestTelemetryTracker:
  def test_tracker_initialization(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)

    assert tracker.session_id is not None
    assert tracker.session_id.startswith("session_")

    assert isinstance(tracker.start_time, datetime)

    assert isinstance(tracker.network_info, NetworkInfo)
    assert tracker.network_info.source_ip == source_ip
    assert tracker.network_info.source_port == source_port
    assert tracker.network_info.ssh_client == client_version
  
  def test_add_authentication(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")

    assert tracker.auth_info is not None
    assert tracker.auth_info.username == "root"
    assert tracker.auth_info.password == "password"
    assert isinstance(tracker.auth_info.timestamp, datetime)
  
  def test_add_environment(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    terminal_type = "xterm"
    shell_width = 80
    shell_height = 24
    tracker.add_environment(terminal_type, shell_width, shell_height)

    assert tracker.env_info is not None
    assert tracker.env_info.terminal_type == terminal_type
    assert tracker.env_info.shell_width == shell_width
    assert tracker.env_info.shell_height == shell_height
  
  def test_add_interaction(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    commands = ["ls -la", "cat /etc/passwd"]
    backspaces = [0, 2]
    tracker.add_interaction(commands[0], backspaces[0])
    tracker.add_interaction(commands[1], backspaces[1])

    assert len(tracker.interactions) == 2
    interaction_1 = tracker.interactions[0]
    assert isinstance(interaction_1, InteractionInfo)
    assert interaction_1.command == commands[0]
    assert interaction_1.backspaces == backspaces[0]
    interaction_2 = tracker.interactions[1]
    assert isinstance(interaction_2, InteractionInfo)
    assert interaction_2.command == commands[1]
    assert interaction_2.backspaces == backspaces[1]
    assert isinstance(interaction_2.timestamp, datetime)
  
  @patch("src.honeyengage.telemetry.tracker.MitreMapper.evaluate_command")
  def test_finalize_and_export(self, mock_evaluate_command):
    mock_evaluate_command.return_value = MitreMapping(
      technique_id="T9999",
      confidence=0.99,
      cti_sentence="This is a fast mock sentence for testing."
    )

    engage_parser = MagicMock()
    engage_mapper = MagicMock()

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")
    tracker.add_environment("xterm", 60, 18)
    tracker.add_interaction("whoami", 3)

    exit_reason = "User requested logout"
    session_json = tracker.finalize_and_export(exit_reason)

    assert isinstance(session_json, str)

    mock_evaluate_command.assert_called_once()
    called_args, _ = mock_evaluate_command.call_args
    assert called_args[0] == "whoami"
    assert len(called_args[1]) == 1
    assert called_args[1][0].command == "whoami"
        
    assert "technique_id" in session_json
    assert "confidence" in session_json
    assert "cti_sentence" in session_json

    session_data = Session.model_validate_json(session_json)

    assert session_data.session_id == tracker.session_id
    assert session_data.network.source_ip == source_ip
    assert session_data.network.source_port == source_port
    assert session_data.network.ssh_client == client_version
    assert session_data.environment.terminal_type == "xterm"
    assert session_data.environment.shell_width == 60
    assert session_data.environment.shell_height == 18
    assert session_data.authentication.username == "root"
    assert session_data.authentication.password == "password"
    assert len(session_data.interactions) == 1
    assert session_data.interactions[0].command == "whoami"
    assert session_data.interactions[0].backspaces == 3
    assert session_data.session_metadata.exit_reason == exit_reason
  
  @patch("src.honeyengage.telemetry.tracker.MitreMapper.evaluate_command")
  def test_finalize_without_authentication(self, mock_evaluate_command):
    mock_evaluate_command.return_value = []

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    tracker.add_environment("xterm", 60, 18)
    tracker.add_interaction("pwd", 0)

    with pytest.raises(ValueError, match="Authentication information is missing"):
      tracker.finalize_and_export("User requested logout")
  
  @patch("src.honeyengage.telemetry.tracker.MitreMapper.evaluate_command")
  def test_finalize_without_environment(self, mock_evaluate_command):
    mock_evaluate_command.return_value = []

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")
    tracker.add_interaction("pwd", 0)

    with pytest.raises(ValueError, match="Environment information is missing"):
      tracker.finalize_and_export("User requested logout")
  
  def test_pydantic_validation(self):
    with pytest.raises(ValidationError):
      NetworkInfo(source_ip=123, source_port="not_a_port", ssh_client="asdfg") # type: ignore

  @patch("src.honeyengage.telemetry.tracker.MitreMapper.evaluate_command")
  def test_add_interaction_skips_engage_without_session_environment(self, mock_evaluate_command):
    mock_evaluate_command.return_value = MitreMapping(
      technique_id="T9999",
      confidence=0.99,
      cti_sentence="High confidence mapping without a bound session environment.",
    )

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")
    tracker.add_environment("xterm", 60, 18)

    assert tracker.vfs is None
    assert tracker.virtual_shell is None

    tracker.add_interaction("whoami", 0)
    tracker.finalize_and_export("User requested logout")

    engage_mapper.evaluate_and_react.assert_not_called()

  def test_set_session_environment_binds_vfs_and_shell(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    session_vfs = MagicMock()
    session_shell = MagicMock()

    tracker.set_session_environment(session_vfs, session_shell)

    assert tracker.vfs is session_vfs
    assert tracker.virtual_shell is session_shell

  @patch("src.honeyengage.telemetry.tracker.MitreMapper.evaluate_command")
  def test_add_interaction_reacts_with_this_sessions_vfs_and_shell(self, mock_evaluate_command):
    mock_evaluate_command.return_value = MitreMapping(
      technique_id="T9999",
      confidence=0.99,
      cti_sentence="High confidence mapping bound to this session's environment.",
    )

    local_engage_parser = MagicMock()
    local_engage_parser.get_engage_activities_for_technique.return_value = ["some-activity"]
    local_engage_engine = MagicMock()

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, local_engage_parser, local_engage_engine)
    tracker.add_authentication("root", "password")
    tracker.add_environment("xterm", 60, 18)

    this_session_vfs = MagicMock(name="this_session_vfs")
    this_session_shell = MagicMock(name="this_session_shell")
    tracker.set_session_environment(this_session_vfs, this_session_shell)

    tracker.add_interaction("whoami", 0)
    tracker.finalize_and_export("User requested logout")

    local_engage_engine.evaluate_and_react.assert_called_once()
    call_args = local_engage_engine.evaluate_and_react.call_args.args
    assert this_session_vfs in call_args
    assert this_session_shell in call_args
    vfs_index = call_args.index(this_session_vfs)
    assert call_args[vfs_index + 2] == []

class TestAsynchronousAnalysis:
  def test_add_interaction_returns_immediately_and_runs_analyses_in_order(self):
    import threading
    import time

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, engage_parser, engage_mapper)
    started, running, overlaps = [], [0], [0]
    lock = threading.Lock()

    def slow_evaluate(command, interactions):
      with lock:
        running[0] += 1
        overlaps[0] = max(overlaps[0], running[0])
        started.append(command)
      time.sleep(0.2)
      with lock:
        running[0] -= 1
      return None

    tracker.mitre_mapper = MagicMock()
    tracker.mitre_mapper.evaluate_command.side_effect = slow_evaluate

    t0 = time.monotonic()
    for command in ("whoami", "id", "uname -a"):
      tracker.add_interaction(command, 0)
    assert time.monotonic() - t0 < 0.1

    for thread in tracker.analysis_threads:
      thread.join()
    assert started == ["whoami", "id", "uname -a"]
    assert overlaps[0] == 1
