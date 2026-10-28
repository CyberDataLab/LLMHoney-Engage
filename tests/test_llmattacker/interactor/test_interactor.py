from unittest.mock import MagicMock, patch

from src.llmattacker.interactor.interactor import Interactor


class TestInteractor:
  def test_init_sets_connection_parameters(self):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")

    assert interactor.host == "127.0.0.1"
    assert interactor.port == 2222
    assert interactor.username == "user"
    assert interactor.password == "pass"
    assert interactor.shell is None

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_connect_success(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    interactor.ssh_client = MagicMock()
    mock_shell = MagicMock()
    mock_shell.recv_ready.return_value = False
    interactor.ssh_client.invoke_shell.return_value = mock_shell

    result = interactor.connect()

    assert result is True
    assert interactor.shell is mock_shell
    interactor.ssh_client.connect.assert_called_once_with(
      hostname="127.0.0.1", port=2222, username="user", password="pass", timeout=10
    )

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_connect_drains_welcome_message(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    interactor.ssh_client = MagicMock()
    mock_shell = MagicMock()
    mock_shell.recv_ready.return_value = True
    mock_shell.recv.return_value = b"Welcome to Ubuntu 22.04\n"
    interactor.ssh_client.invoke_shell.return_value = mock_shell

    result = interactor.connect()

    assert result is True
    mock_shell.recv.assert_called_once_with(4096)

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_connect_failure_returns_false(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    interactor.ssh_client = MagicMock()
    interactor.ssh_client.connect.side_effect = ConnectionRefusedError("refused")

    result = interactor.connect()

    assert result is False
    assert interactor.shell is None

  def test_execute_command_raises_without_connection(self):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")

    try:
      interactor.execute_command("whoami")
      raise AssertionError("Expected ConnectionError")
    except ConnectionError as e:
      assert "Not connected" in str(e)

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_execute_command_sends_command_with_newline(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    mock_shell = MagicMock()
    mock_shell.recv_ready.return_value = False
    interactor.shell = mock_shell

    interactor.execute_command("whoami")

    mock_shell.send.assert_called_once_with(b"whoami\n")

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_execute_command_drains_and_strips_output(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    mock_shell = MagicMock()
    ready_sequence = iter([False, True, True, False])
    mock_shell.recv_ready.side_effect = lambda: next(ready_sequence, False)
    mock_shell.recv.side_effect = [b"  root\r\n", b"\r\n"]
    interactor.shell = mock_shell

    output = interactor.execute_command("whoami")

    assert output == "root"

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_execute_command_polls_until_data_or_max_wait_time(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    mock_shell = MagicMock()
    mock_shell.recv_ready.return_value = False
    interactor.shell = mock_shell

    interactor.execute_command("whoami", max_wait_time=1.0)

    poll_sleep_calls = [c for c in mock_sleep.call_args_list if c.args == (0.1,)]
    assert len(poll_sleep_calls) >= 9

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_disconnect_sends_exit_and_closes(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    mock_shell = MagicMock()
    interactor.shell = mock_shell
    interactor.ssh_client = MagicMock()

    interactor.disconnect()

    mock_shell.send.assert_called_once_with(b"exit\n")
    interactor.ssh_client.close.assert_called_once()

  @patch("src.llmattacker.interactor.interactor.time.sleep")
  def test_disconnect_without_shell_still_closes_client(self, mock_sleep):
    interactor = Interactor(host="127.0.0.1", port=2222, username="user", password="pass")
    interactor.ssh_client = MagicMock()

    interactor.disconnect()

    interactor.ssh_client.close.assert_called_once()
