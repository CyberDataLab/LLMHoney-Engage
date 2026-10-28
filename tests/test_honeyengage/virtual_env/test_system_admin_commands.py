import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import ProcessData, VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  root_dir = FSDirectory("root")
  secret = FSFile("secret.txt", uid=0, gid=0, size=10)
  root_dir.add_child(secret)

  vfs.root.add_child(root_dir)
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


class TestChown:
  def test_changes_uid_and_gid_for_known_user(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    node = vfs.get_node("/root/secret.txt")

    shell.execute_command("chown daniel:daniel secret.txt")

    assert node.uid == 1000
    assert node.gid == 1000

  def test_owner_only_spec_leaves_group_unchanged(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    node = vfs.get_node("/root/secret.txt")

    shell.execute_command("chown daniel secret.txt")

    assert node.uid == 1000
    assert node.gid == 0

  def test_numeric_owner_spec_is_used_directly(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    node = vfs.get_node("/root/secret.txt")

    shell.execute_command("chown 1500:1500 secret.txt")

    assert node.uid == 1500
    assert node.gid == 1500

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("chown root nonexistent.txt")
    assert "cannot access" in output

  def test_missing_arguments_reports_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("chown")
    assert "Usage" in output


class TestChgrp:
  def test_changes_only_gid(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    node = vfs.get_node("/root/secret.txt")

    shell.execute_command("chgrp daniel secret.txt")

    assert node.gid == 1000
    assert node.uid == 0

  def test_missing_arguments_reports_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("chgrp")
    assert "Usage" in output


class TestKill:
  def test_kills_process_by_pid(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.process_list.append(ProcessData(
      user="root", pid=5555, cpu_usage=0.0, memory_usage=0.0, vsz=0, rss=0,
      tty="tty1", stat="S", start_time="00:00", time="0:00", command="malicious-beacon",
    ))

    shell.execute_command("kill 5555")

    assert not any(p.pid == 5555 for p in shell.process_list)

  def test_kill_nonexistent_pid_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("kill 424242")
    assert "No such process" in output

  def test_missing_arguments_reports_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("kill")
    assert "usage" in output


class TestPkillAndKillall:
  def test_pkill_removes_matching_processes_by_command_name(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.process_list.append(ProcessData(
      user="root", pid=6666, cpu_usage=0.0, memory_usage=0.0, vsz=0, rss=0,
      tty="tty1", stat="S", start_time="00:00", time="0:00", command="/tmp/cnc-beacon",
    ))

    shell.execute_command("pkill cnc-beacon")

    assert not any(p.pid == 6666 for p in shell.process_list)

  def test_killall_is_alias_for_pkill(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.process_list.append(ProcessData(
      user="root", pid=7777, cpu_usage=0.0, memory_usage=0.0, vsz=0, rss=0,
      tty="tty1", stat="S", start_time="00:00", time="0:00", command="sshd",
    ))

    shell.execute_command("killall sshd")

    assert not any(p.pid == 7777 for p in shell.process_list)


class TestExportAndUnset:
  def test_export_sets_environment_variable(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.execute_command("export FOO=bar")
    assert shell.environ["FOO"] == "bar"

  def test_exported_variable_is_visible_to_later_command(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("export FOO=bar && echo $FOO")
    assert "bar" in output

  def test_unset_removes_environment_variable(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.environ["FOO"] = "bar"
    shell.execute_command("unset FOO")
    assert "FOO" not in shell.environ


class TestSu:
  def test_su_changes_current_user(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.execute_command("su daniel")
    assert shell.current_user == "daniel"

  def test_su_without_argument_defaults_to_root(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.execute_command("su daniel")
    shell.execute_command("su")
    assert shell.current_user == "root"

  def test_su_propagates_to_cowrie_backed_whoami(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("su daniel && whoami")
    assert "daniel" in output

  def test_su_propagates_correct_uid_to_cowrie_backed_id(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("su daniel && id")
    assert "uid=1000(daniel)" in output
