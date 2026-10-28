from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from paramiko.common import AUTH_SUCCESSFUL, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED

from src.honeyengage.sensor.sensor import Sensor, handle_session
from src.honeyengage.telemetry.models import InteractionInfo
from src.honeyengage.virtual_env.virtual_shell import ShellTerminationError


class TestHoneyEngageSensor:
  @pytest.fixture
  def tracker(self):
    return MagicMock()
  
  @pytest.fixture
  def sensor(self, tracker):
    return Sensor(tracker)
  
  def test_check_channel_request(self, sensor, tracker):
    assert sensor.check_channel_request("session", 1) == OPEN_SUCCEEDED
    assert sensor.check_channel_request("invalid", 1) == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  
  def test_check_auth_password(self, sensor, tracker):
    assert sensor.check_auth_password("user", "pass") == AUTH_SUCCESSFUL
  
  def test_get_allowed_auths(self, sensor, tracker):
    assert sensor.get_allowed_auths("user") == "password"
  
  def test_check_channel_pty_request(self, sensor, tracker):
    mock_channel = MagicMock()
    assert sensor.check_channel_pty_request(mock_channel, b"xterm", 80, 24, 0, 0, b"") is True
  
  def test_check_channel_shell_request(self, sensor, tracker):
    mock_channel = MagicMock()
    assert sensor.check_channel_shell_request(mock_channel) is True
  
  def test_handle_session_exit_command(self, sensor, tracker):
    mock_channel = MagicMock()
    mock_shell = MagicMock()
    mock_channel.recv.side_effect = [b'e', b'x', b'i', b't', b'\n', b'']
    
    fake_ip = ("192.168.1.100", 55555)
    handle_session(mock_channel, fake_ip, tracker, mock_shell)
    
    mock_channel.send.assert_any_call(b"logout\r\n")
    mock_channel.close.assert_called_once()
  
  def test_session_exit_command(self, sensor, tracker):
    mock_channel = MagicMock()
    mock_tracker = MagicMock()
    mock_shell = MagicMock()
    mock_addr = ("192.168.1.50", 54321)
    mock_channel.recv.side_effect = [b"e", b"x", b"i", b"t", b"\r", b""]

    handle_session(mock_channel, mock_addr, mock_tracker, mock_shell)

    mock_channel.send.assert_any_call(b"logout\r\n")

  def test_session_logout_command(self, sensor, tracker):
    mock_channel = MagicMock()
    mock_tracker = MagicMock()
    mock_shell = MagicMock()
    mock_addr = ("192.168.1.50", 54321)

    mock_channel.recv.side_effect = [b"l", b"o", b"g", b"o", b"u", b"t", b"\r", b""]

    handle_session(mock_channel, mock_addr, mock_tracker, mock_shell)

    mock_channel.send.assert_any_call(b"logout\r\n")

  def test_session_shutdown_command_closes_connection(self, sensor, tracker):
    mock_channel = MagicMock()
    mock_tracker = MagicMock()
    mock_shell = MagicMock()
    mock_addr = ("192.168.1.50", 54321)

    mock_channel.recv.side_effect = [b"r", b"e", b"b", b"o", b"o", b"t", b"\r", b""]
    mock_shell.execute_command.side_effect = ShellTerminationError(
      "\r\nBroadcast message from root@ubuntu (pts/0) (Mon Jan 01 00:00:00 2026):\r\n\r\nThe system is going down for reboot NOW!\r\n",
      "System reboot requested",
    )

    handle_session(mock_channel, mock_addr, mock_tracker, mock_shell)

    mock_channel.send.assert_any_call(b"\r\nBroadcast message from root@ubuntu (pts/0) (Mon Jan 01 00:00:00 2026):\r\n\r\nThe system is going down for reboot NOW!\r\n")
    mock_channel.close.assert_called_once()

  def test_command_response_is_captured_on_the_interaction(self, sensor, tracker):
    mock_channel = MagicMock()
    mock_tracker = MagicMock()
    mock_shell = MagicMock()
    mock_addr = ("192.168.1.50", 54321)

    interaction = InteractionInfo(
      command="whoami", timestamp=datetime.now(UTC), backspaces=0, response=None,
    )
    mock_tracker.add_interaction.return_value = (interaction, None)

    def fake_execute_command(command: str) -> str:
      recorder = mock_shell.set_command_recorder.call_args.args[0]
      recorder(command)
      return "root\r\n"

    mock_shell.execute_command.side_effect = fake_execute_command
    mock_channel.recv.side_effect = [b"w", b"h", b"o", b"a", b"m", b"i", b"\r", b"e", b"x", b"i", b"t", b"\r", b""]

    handle_session(mock_channel, mock_addr, mock_tracker, mock_shell)

    assert interaction.response == "root\r\n"

  def test_termination_output_is_captured_on_the_interaction(self, sensor, tracker):
    mock_channel = MagicMock()
    mock_tracker = MagicMock()
    mock_shell = MagicMock()
    mock_addr = ("192.168.1.50", 54321)

    interaction = InteractionInfo(
      command="reboot", timestamp=datetime.now(UTC), backspaces=0, response=None,
    )
    mock_tracker.add_interaction.return_value = (interaction, None)
    termination_output = "\r\nBroadcast message from root@ubuntu (pts/0):\r\n\r\nThe system is going down for reboot NOW!\r\n"

    def fake_execute_command(command: str) -> str:
      recorder = mock_shell.set_command_recorder.call_args.args[0]
      recorder(command)
      raise ShellTerminationError(termination_output, "System reboot requested")

    mock_shell.execute_command.side_effect = fake_execute_command
    mock_channel.recv.side_effect = [b"r", b"e", b"b", b"o", b"o", b"t", b"\r", b""]

    handle_session(mock_channel, mock_addr, mock_tracker, mock_shell)

    assert interaction.response == termination_output