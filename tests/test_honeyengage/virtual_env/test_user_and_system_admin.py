import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  root_dir = FSDirectory("root")
  vfs.root.add_child(root_dir)
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


class TestUsermod:
  def test_changes_uid_reflected_in_subsequent_id_call(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.execute_command("usermod -u 1500 daniel")
    output = shell.execute_command("su daniel && id")
    assert "uid=1500(daniel)" in output


class TestGroupaddGroupdel:
  def test_groupadd_succeeds_silently(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("groupadd devops")
    assert output == ""

  def test_groupadd_existing_group_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.execute_command("groupadd devops")
    output = shell.execute_command("groupadd devops")
    assert "already exists" in output

  def test_groupdel_removes_group(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.execute_command("groupadd devops")
    output = shell.execute_command("groupdel devops")
    assert output == ""

  def test_groupdel_nonexistent_group_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("groupdel nonexistent")
    assert "does not exist" in output


class TestDpkg:
  def test_list_shows_package_table(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("dpkg -l")
    assert "ii" in output
    assert "Version" in output

  def test_list_filters_by_package_name(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("dpkg -l curl")
    assert "curl" in output


class TestSystemInspection:
  def test_lsblk_shows_block_devices(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("lsblk")
    assert "sda" in output

  def test_lsmod_shows_kernel_modules(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("lsmod")
    assert "Module" in output

  def test_dmesg_shows_kernel_log(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("dmesg")
    assert "Linux version" in output

  def test_vmstat_shows_process_count_from_process_list(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("vmstat")
    assert "procs" in output

  def test_ldd_shows_shared_library_dependencies(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ldd /bin/ls")
    assert "libc.so" in output

  def test_ldd_without_argument_shows_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ldd")
    assert "Usage" in output


class TestVisudo:
  def test_check_flag_reports_ok(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("visudo -c")
    assert "parsed OK" in output


class TestAt:
  def test_scheduling_a_job_reports_job_id(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("at now + 1 minute")
    assert output.startswith("job ")


class TestPython3Alias:
  def test_python3_is_aliased_to_python(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("python3 --version")
    assert "Python" in output
