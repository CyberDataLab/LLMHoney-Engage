import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  root_dir = FSDirectory("root")
  logfile = FSFile("app.log", content="INFO starting\nERROR disk full\nINFO done\nERROR disk full\n")
  root_dir.add_child(logfile)

  vfs.root.add_child(root_dir)
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


def test_semicolon_runs_both_commands_regardless_of_outcome(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("echo first ; echo second")
  assert "first" in output
  assert "second" in output


def test_semicolon_runs_second_command_even_if_first_fails(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("nonexistentcmd123 ; echo still-runs")
  assert "command not found" in output
  assert "still-runs" in output


def test_and_runs_second_command_when_first_succeeds(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("whoami && echo yes")
  assert "root" in output
  assert "yes" in output


def test_and_skips_second_command_when_first_fails(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("nonexistentcmd123 && echo should-not-appear")
  assert "should-not-appear" not in output


def test_or_skips_second_command_when_first_succeeds(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("whoami || echo should-not-appear")
  assert "should-not-appear" not in output


def test_or_runs_second_command_when_first_fails(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("nonexistentcmd123 || echo fallback-ran")
  assert "fallback-ran" in output


def test_chained_and_or_matches_bash_short_circuit_semantics(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("nonexistentcmd123 && echo a || echo b && echo c")
  assert "a\r\n" not in output
  assert "b" in output
  assert "c" in output


def test_pipe_feeds_output_of_first_command_as_input_to_second(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("cat app.log | grep ERROR")
  assert "ERROR disk full" in output
  assert "INFO" not in output


def test_pipe_chain_with_three_stages(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("cat app.log | grep ERROR | wc -l")
  assert output.strip() == "2"


def test_native_head_reads_from_stdin_when_no_file_given(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("cat app.log | head -n 1")
  assert output.strip() == "INFO starting"


def test_native_tail_reads_from_stdin_when_no_file_given(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("cat app.log | tail -n 1")
  assert output.strip() == "ERROR disk full"


def test_native_wc_reads_from_stdin_when_no_file_given(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("cat app.log | wc -l")
  assert output.strip() == "4"


def test_grep_without_file_or_stdin_shows_usage(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("grep ERROR")
  assert "Usage" in output


def test_pipe_character_inside_quotes_is_not_treated_as_operator(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command('echo "a | b"')
  assert output.strip() == "a | b"


def test_semicolon_inside_quotes_is_not_treated_as_operator(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command('echo "a; b"')
  assert output.strip() == "a; b"


def test_redirection_target_is_visible_to_later_command_in_sequence(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("echo hello > /root/out.txt ; cat /root/out.txt")
  assert "hello" in output
