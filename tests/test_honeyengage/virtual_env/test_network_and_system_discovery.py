import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import NetworkConnection, VirtualShell


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


class TestNetstat:
  def test_shows_seeded_connection_by_default(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("netstat")
    assert "127.0.0.1:8080" in output
    assert "ESTABLISHED" in output

  def test_reflects_injected_fake_connection(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.network_connections.append(NetworkConnection(
      protocol="TCP", local_address="0.0.0.0:31337", remote_address="203.0.113.55:4444", state="ESTABLISHED"
    ))
    output = shell.execute_command("netstat")
    assert "203.0.113.55:4444" in output

  def test_listen_filter_excludes_established_connections(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("netstat -tuln")
    assert "ESTABLISHED" not in output

  def test_listen_filter_includes_listening_connections(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.network_connections.append(NetworkConnection(
      protocol="TCP", local_address="0.0.0.0:22", remote_address="0.0.0.0:*", state="LISTEN"
    ))
    output = shell.execute_command("netstat -tuln")
    assert "0.0.0.0:22" in output

  def test_route_subcommand_shows_routing_table(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("netstat route")
    assert "Destination" in output
    assert "Gateway" in output


class TestSs:
  def test_reflects_injected_fake_connection(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.network_connections.append(NetworkConnection(
      protocol="TCP", local_address="0.0.0.0:31337", remote_address="203.0.113.55:4444", state="ESTABLISHED"
    ))
    output = shell.execute_command("ss -t")
    assert "203.0.113.55:4444" in output

  def test_udp_only_filter_excludes_tcp_connections(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ss -u")
    assert "127.0.0.1:8080" not in output


class TestLsof:
  def test_dash_i_reflects_injected_fake_connection(self, vfs_and_shell):
    _, shell = vfs_and_shell
    shell.network_connections.append(NetworkConnection(
      protocol="TCP", local_address="0.0.0.0:31337", remote_address="203.0.113.55:4444", state="ESTABLISHED"
    ))
    output = shell.execute_command("lsof -i")
    assert "203.0.113.55:4444" in output

  def test_without_arguments_returns_header_only(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("lsof")
    assert "COMMAND" in output


class TestIp:
  def test_addr_shows_loopback_and_eth0(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ip addr")
    assert "lo:" in output
    assert "eth0:" in output
    assert "127.0.0.1" in output

  def test_route_shows_default_gateway(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ip route")
    assert "default via" in output

  def test_unknown_object_reports_error(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ip bogus")
    assert "unknown" in output

  def test_missing_object_shows_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("ip")
    assert "Usage" in output


class TestDf:
  def test_shows_filesystem_table(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("df")
    assert "Filesystem" in output
    assert "/dev/sda1" in output

  def test_human_readable_flag_uses_size_suffixes(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("df -h")
    assert "20G" in output


class TestMount:
  def test_without_arguments_lists_mounted_filesystems(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("mount")
    assert "/dev/sda1 on /" in output

  def test_mounting_a_device_succeeds_silently(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("mount /dev/sdb1 /mnt")
    assert output == ""


class TestSystemctl:
  def test_list_units_shows_unit_table(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemctl list-units")
    assert "ssh.service" in output

  def test_start_succeeds_silently(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemctl start cron.service")
    assert output == ""

  def test_status_reports_active_for_a_real_unit(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemctl status ssh")
    assert "active (running)" in output

  def test_status_reports_not_found_for_an_unknown_unit(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemctl status totally-made-up-service")
    assert "could not be found" in output

  def test_missing_arguments_shows_usage(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("systemctl")
    assert "Usage" in output


class TestJournalctl:
  def test_returns_log_lines(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("journalctl -u sshd")
    assert "sshd" in output


class TestTop:
  def test_shows_process_table_from_process_list(self, vfs_and_shell):
    _, shell = vfs_and_shell
    output = shell.execute_command("top")
    assert "bash" in output
    assert "/sbin/init" in output
    assert "Tasks:" in output
