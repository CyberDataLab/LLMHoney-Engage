import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  tmp_dir = FSDirectory("tmp")
  root_dir = FSDirectory("root")
  vfs.root.add_child(tmp_dir)
  vfs.root.add_child(root_dir)

  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


class TestWget:
  def test_saves_to_explicit_output_path(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("wget -O /tmp/payload.sh https://example.com/payload.sh")

    assert vfs.exists("/tmp/payload.sh")

  def test_saves_to_basename_of_url_without_output_flag(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("wget https://example.com/files/tool.tar.gz")

    assert vfs.exists("/root/tool.tar.gz")

  def test_reports_success_message(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("wget -O /tmp/x.sh https://example.com/x.sh")

    assert "saved" in output
    assert "200 OK" in output

  def test_missing_url_reports_usage_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("wget")

    assert "missing URL" in output


class TestCurl:
  def test_dash_o_uppercase_saves_using_url_basename(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("curl -O https://example.com/repo/archive/rev.zip")

    assert vfs.exists("/root/rev.zip")

  def test_dash_o_lowercase_saves_to_explicit_path(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("curl -o /tmp/out.zip https://example.com/rev.zip")

    assert vfs.exists("/tmp/out.zip")

  def test_without_output_flag_writes_to_stdout(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    output = shell.execute_command("curl https://example.com/")

    assert output.strip() != ""
    assert not vfs.exists("/root/index.html")

  def test_combined_with_and_operator_lets_downstream_command_read_the_file(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("curl -sLO https://example.com/rev.zip && echo done")

    assert "done" in output


class TestTftp:
  def test_get_flag_saves_file(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("tftp --get=firmware.bin 10.0.0.1")

    assert vfs.exists("/root/firmware.bin")

  def test_positional_get_target_saves_file(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("tftp -i 10.0.0.1 GET update.bin")

    assert vfs.exists("/root/update.bin")

  def test_missing_target_reports_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("tftp")

    assert "usage" in output


class TestFtpget:
  def test_saves_local_file(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("ftpget 10.0.0.1 local_copy.tar remote_copy.tar")

    assert vfs.exists("/root/local_copy.tar")

  def test_missing_arguments_reports_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ftpget 10.0.0.1")

    assert "Usage" in output


class TestNc:
  def test_listener_reports_listening_without_blocking(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("nc -l -p 4444")

    assert "listening" in output
    assert "4444" in output

  def test_verbose_connect_to_closed_port_reports_refused(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("nc -nv 10.0.0.5 8080")

    assert "refused" in output.lower()

  def test_non_verbose_connect_returns_silently(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("nc 10.0.0.5 8080")

    assert output == ""

  def test_missing_arguments_reports_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("nc")

    assert "usage" in output
