import bz2
import gzip
import io
import zipfile

import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  root_dir = FSDirectory("root")
  data_file = FSFile("data.txt", content="sensitive information here")
  root_dir.add_child(data_file)

  vfs.root.add_child(root_dir)
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


class TestVfsBinaryContentRoundTrip:

  def test_arbitrary_binary_content_round_trips_exactly(self, vfs_and_shell):
    vfs, _ = vfs_and_shell
    all_byte_values = bytes(range(256))
    vfs.override_file_contents("/root/data.txt", all_byte_values)
    assert vfs.file_contents("/root/data.txt") == all_byte_values

  def test_gzip_compressed_bytes_round_trip(self, vfs_and_shell):
    vfs, _ = vfs_and_shell
    compressed = gzip.compress(b"arbitrary binary payload \x00\x01\xff\xfe")
    vfs.override_file_contents("/root/data.txt", compressed)
    assert vfs.file_contents("/root/data.txt") == compressed


class TestGzip:
  def test_dash_k_keeps_original_and_creates_gz(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("gzip -k data.txt")
    assert vfs.exists("/root/data.txt")
    assert vfs.exists("/root/data.txt.gz")

  def test_without_dash_k_removes_original(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("gzip data.txt")
    assert not vfs.exists("/root/data.txt")
    assert vfs.exists("/root/data.txt.gz")

  def test_compressed_content_decompresses_to_original_bytes(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("gzip -k data.txt")
    compressed = vfs.file_contents("/root/data.txt.gz")
    assert gzip.decompress(compressed) == b"sensitive information here"

  def test_dash_d_decompresses_back_to_original_bytes(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("gzip -k data.txt")
    shell.execute_command("rm data.txt")
    shell.execute_command("gzip -d -k data.txt.gz")
    assert vfs.file_contents("/root/data.txt") == b"sensitive information here"

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("gzip missing.txt")
    assert "No such file or directory" in output


class TestBzip2:
  def test_dash_k_keeps_original_and_creates_bz2(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("bzip2 -k data.txt")
    assert vfs.exists("/root/data.txt")
    assert vfs.exists("/root/data.txt.bz2")

  def test_compressed_content_decompresses_to_original_bytes(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("bzip2 -k data.txt")
    compressed = vfs.file_contents("/root/data.txt.bz2")
    assert bz2.decompress(compressed) == b"sensitive information here"


class TestZip:
  def test_creates_archive_with_all_members(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("other.txt", content="more data"))

    shell.execute_command("zip archive.zip data.txt other.txt")

    assert vfs.exists("/root/archive.zip")
    archive_bytes = vfs.file_contents("/root/archive.zip")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
      assert set(archive.namelist()) == {"data.txt", "other.txt"}
      assert archive.read("data.txt") == b"sensitive information here"

  def test_appends_dot_zip_extension_if_missing(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("zip archive data.txt")
    assert vfs.exists("/root/archive.zip")

  def test_no_valid_members_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("zip archive.zip missing.txt")
    assert "Nothing to do" in output

  def test_missing_arguments_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("zip archive.zip")
    assert "Nothing to do" in output


class TestUfw:
  def test_status_shows_active_firewall(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ufw status")
    assert "Status: active" in output

  def test_allow_rule_reports_added(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ufw allow 8080/tcp")
    assert "Rule added" in output

  def test_invalid_command_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ufw bogus")
    assert "ERROR" in output


class TestAuditctl:
  def test_list_rules_shows_identity_watches(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("auditctl -l")
    assert "/etc/passwd" in output

  def test_status_flag_shows_daemon_status(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("auditctl -s")
    assert "enabled" in output


class TestSystemdRun:
  def test_reports_transient_unit_name(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemd-run /bin/bash -c 'echo hi'")
    assert "Running as unit:" in output

  def test_missing_command_shows_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemd-run")
    assert "Usage" in output
