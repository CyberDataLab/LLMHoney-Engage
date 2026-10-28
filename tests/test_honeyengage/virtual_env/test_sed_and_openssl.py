import re

import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")

  root_dir = FSDirectory("root")
  conf = FSFile("pam.conf", content="line1\nauth required pam_unix.so\nline3\n")
  root_dir.add_child(conf)

  vfs.root.add_child(root_dir)
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"

  shell = VirtualShell(vfs)
  return vfs, shell


class TestSed:
  def test_substitution_prints_to_stdout_without_i_flag(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    output = shell.execute_command("sed 's/line1/REPLACED/' pam.conf")
    assert output == "REPLACED\nauth required pam_unix.so\nline3\n"
    assert vfs.file_contents("/root/pam.conf") == b"line1\nauth required pam_unix.so\nline3\n"

  def test_dash_i_deletion_mutates_file_in_place(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("sed -i '/auth required/d' pam.conf")
    assert vfs.file_contents("/root/pam.conf") == b"line1\nline3\n"

  def test_dash_i_substitution_mutates_file_in_place(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("sed -i 's/line1/REPLACED/' pam.conf")
    assert vfs.file_contents("/root/pam.conf") == b"REPLACED\nauth required pam_unix.so\nline3\n"

  def test_dash_i_does_not_consume_the_script_as_its_argument(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sed -i '/auth required/d' pam.conf")
    assert output == ""

  def test_reads_from_stdin_in_a_pipe(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("echo hello world | sed 's/world/there/'")
    assert output.strip() == "hello there"

  def test_global_flag_replaces_all_occurrences(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("repeats.txt", content="aaa\n"))
    output = shell.execute_command("sed 's/a/b/g' repeats.txt")
    assert output == "bbb\n"

  def test_without_global_flag_replaces_first_occurrence_only(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    vfs.current_directory.add_child(FSFile("repeats.txt", content="aaa\n"))
    output = shell.execute_command("sed 's/a/b/' repeats.txt")
    assert output == "baa\n"

  def test_missing_file_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("sed 's/a/b/' missing.txt")
    assert "No such file" in output


class TestOpenssl:
  def test_passwd_produces_sha512_crypt_style_hash(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("openssl passwd mypassword")
    assert re.match(r"^\$6\$[0-9a-f]+\$[0-9a-f]+\n$", output)

  def test_passwd_same_salt_is_deterministic(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("openssl passwd -salt abc123 mypassword")
    assert output.startswith("$6$abc123$")

  def test_enc_base64_encodes_stdin(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("echo -n secretdata | openssl enc -base64")
    assert output.strip() == "c2VjcmV0ZGF0YQ=="

  def test_enc_with_out_writes_file(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("openssl enc -base64 -in pam.conf -out /root/pam.conf.enc")
    assert vfs.exists("/root/pam.conf.enc")

  def test_genrsa_with_out_writes_pem_file(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    shell.execute_command("openssl genrsa -out /root/key.pem 2048")
    assert vfs.exists("/root/key.pem")
    content = vfs.file_contents("/root/key.pem").decode()
    assert content.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert content.rstrip().endswith("-----END RSA PRIVATE KEY-----")

  def test_genrsa_without_out_prints_to_stdout(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("openssl genrsa 2048")
    assert "BEGIN RSA PRIVATE KEY" in output

  def test_dgst_sha256_of_file(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("openssl dgst -sha256 pam.conf")
    assert output.startswith("SHA256(pam.conf)= ")

  def test_version_reports_a_plausible_version_string(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("openssl version")
    assert "OpenSSL" in output

  def test_unknown_subcommand_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("openssl bogus")
    assert "invalid command" in output
