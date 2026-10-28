import re

import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  root_dir = FSDirectory("root")
  data_file = FSFile("data.txt", content="banana\napple\ncherry\napple\n")
  root_dir.add_child(data_file)

  vfs.root.add_child(root_dir)
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


class TestSort:
  def test_sorts_file_lines_alphabetically(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sort data.txt")
    assert output == "apple\napple\nbanana\ncherry\n"

  def test_dash_u_deduplicates_adjacent_sorted_lines(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sort -u data.txt")
    assert output == "apple\nbanana\ncherry\n"

  def test_dash_r_reverses_order(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sort -r data.txt")
    assert output == "cherry\nbanana\napple\napple\n"

  def test_reads_from_stdin_in_a_pipe(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("cat data.txt | sort -u")
    assert output.strip().split("\n") == ["apple", "banana", "cherry"]

  def test_numeric_sort_orders_by_value_not_lexically(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("nums.txt", content="10\n2\n1\n"))
    output = shell.execute_command("sort -n nums.txt")
    assert output == "1\n2\n10\n"


class TestHashCommands:
  def test_md5sum_matches_known_digest(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("md5sum data.txt")
    assert output.startswith("763c338aa6f038f8ef266c493c28b213")
    assert "data.txt" in output

  def test_sha256sum_matches_known_digest(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sha256sum data.txt")
    assert output.startswith("f436c825fec3a18c8105983f22374edf4366b4fb2f525d82a3a91dadf6911fa1")

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sha1sum missing.txt")
    assert "No such file or directory" in output

  def test_reads_from_stdin_in_a_pipe(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("cat data.txt | md5sum")
    assert re.match(r"^[0-9a-f]{32}\s+-\s*$", output)


class TestStat:
  def test_reports_actual_content_size_not_stale_metadata(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    node = vfs.get_node("/root/data.txt")
    assert node.size != len(node.content.encode('utf-8'))

    output = shell.execute_command("stat data.txt")
    assert f"Size: {len(node.content.encode('utf-8'))}" in output

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("stat missing.txt")
    assert "No such file or directory" in output


class TestFile:
  def test_identifies_shell_script_by_shebang(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("run.sh", content="#!/bin/sh\necho hi\n"))
    output = shell.execute_command("file run.sh")
    assert "/bin/sh script" in output

  def test_identifies_elf_binary(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    elf_node = FSFile("payload", content="")
    elf_node.content = "\x7fELF" + "x" * 20
    vfs.current_directory.add_child(elf_node)
    output = shell.execute_command("file payload")
    assert "ELF" in output

  def test_identifies_directory(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("file .")
    assert "directory" in output

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("file missing.txt")
    assert "cannot open" in output


class TestPathUtilities:
  def test_basename_strips_directory(self, vfs_and_shell):
    _, shell = vfs_and_shell
    assert shell.execute_command("basename /root/data.txt") == "data.txt\n"

  def test_basename_strips_suffix(self, vfs_and_shell):
    _, shell = vfs_and_shell
    assert shell.execute_command("basename /root/data.txt .txt") == "data\n"

  def test_dirname_returns_parent_directory(self, vfs_and_shell):
    _, shell = vfs_and_shell
    assert shell.execute_command("dirname /root/data.txt") == "/root\n"

  def test_realpath_resolves_relative_path(self, vfs_and_shell):
    _, shell = vfs_and_shell
    assert shell.execute_command("realpath data.txt") == "/root/data.txt\n"

  def test_readlink_dash_f_resolves_path(self, vfs_and_shell):
    _, shell = vfs_and_shell
    assert shell.execute_command("readlink -f data.txt") == "/root/data.txt\n"


class TestLn:
  def test_creates_hardlink_with_same_content(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("ln data.txt link.txt")
    assert vfs.exists("/root/link.txt")
    assert vfs.file_contents("/root/link.txt") == vfs.file_contents("/root/data.txt")

  def test_missing_target_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ln missing.txt link.txt")
    assert "No such file or directory" in output


class TestTruncate:
  def test_shrinks_file_to_given_size(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("truncate -s 3 data.txt")
    assert vfs.file_contents("/root/data.txt") == b"ban"

  def test_grows_file_padding_with_nulls(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("small.txt", content="hi"))
    shell.execute_command("truncate -s 5 small.txt")
    content = vfs.file_contents("/root/small.txt")
    assert content.startswith(b"hi")
    assert len(content) == 5


class TestXxd:
  def test_produces_hex_and_ascii_columns(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("bin.dat", content="AB"))
    output = shell.execute_command("xxd bin.dat")
    assert "4142" in output
    assert "AB" in output


class TestStrings:
  def test_extracts_printable_runs(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("mixed.bin", content="hello world plain text here"))
    output = shell.execute_command("strings mixed.bin")
    assert "hello world plain text here" in output

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("strings missing.bin")
    assert "No such file or directory" in output
