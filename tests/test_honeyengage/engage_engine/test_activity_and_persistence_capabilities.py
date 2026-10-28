from types import SimpleNamespace

import pytest

from src.honeyengage.engage_engine.capabilities.activity_and_persistence_capabilities import (
  InjectFakeUnixSocketCapability,
  PlantSshAuthorizedKeyCapability,
  SimulateFailedLoginAttemptsCapability,
  SimulateFirewallActivityCapability,
  SimulateServiceFailureCapability,
  SimulateSudoAbuseCapability,
)
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
  shell = VirtualShell(vfs, session_id="test-session", persona_role_id="web_server")
  return vfs, shell


class TestSimulateFailedLoginAttemptsCapability:
  def test_injects_events_visible_in_last(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    capability = SimulateFailedLoginAttemptsCapability(vfs, shell, "EAC0001", SimpleNamespace(attempts=[
      {"username": "admin", "source_ip": "203.0.113.5", "success": False, "timestamp_label": "Jul 14 03:22:10", "method": "password"},
    ]))
    result = capability.execute()

    assert result.success is True
    output = shell.execute_command("last")
    assert "admin" in output
    assert "203.0.113.5" in output

  def test_injects_events_visible_in_journalctl_sshd(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    capability = SimulateFailedLoginAttemptsCapability(vfs, shell, "EAC0001", SimpleNamespace(attempts=[
      {"username": "root", "source_ip": "198.51.100.9", "success": True, "timestamp_label": "Jul 15 11:02:44", "method": "password"},
    ]))
    capability.execute()

    output = shell.execute_command("journalctl -u sshd")
    assert "Accepted password for root from 198.51.100.9" in output

  def test_missing_attempts_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateFailedLoginAttemptsCapability(vfs, shell, "EAC0001", SimpleNamespace()).execute()
    assert result.success is False

  def test_malformed_entries_are_skipped_not_crashed(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateFailedLoginAttemptsCapability(vfs, shell, "EAC0001", SimpleNamespace(attempts=[
      {"username": "admin"},
      {"username": "root", "source_ip": "1.2.3.4", "success": True, "timestamp_label": "Jul 1 00:00:00"},
    ])).execute()
    assert result.success is True
    assert len(shell.login_events) == 1


class TestSimulateServiceFailureCapability:
  def test_marks_existing_unit_as_failed(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateServiceFailureCapability(vfs, shell, "EAC0001", SimpleNamespace(unit_name="cron.service")).execute()

    assert result.success is True
    output = shell.execute_command("systemctl status cron.service")
    assert "failed (failed)" in output

  def test_creates_unit_if_not_already_present(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateServiceFailureCapability(vfs, shell, "EAC0001", SimpleNamespace(
      unit_name="backup-agent.service", description="Nightly backup agent",
    )).execute()

    assert result.success is True
    output = shell.execute_command("systemctl status backup-agent.service")
    assert "failed (failed)" in output

  def test_missing_unit_name_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateServiceFailureCapability(vfs, shell, "EAC0001", SimpleNamespace()).execute()
    assert result.success is False


class TestInjectFakeUnixSocketCapability:
  def test_socket_visible_via_lsof_dash_u(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = InjectFakeUnixSocketCapability(vfs, shell, "EAC0004", SimpleNamespace(
      socket_path="/var/run/docker.sock", process_command="/usr/bin/dockerd",
    )).execute()

    assert result.success is True
    output = shell.execute_command("lsof -U")
    assert "/var/run/docker.sock" in output
    assert "dockerd" in output

  def test_missing_fields_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = InjectFakeUnixSocketCapability(vfs, shell, "EAC0004", SimpleNamespace()).execute()
    assert result.success is False


class TestSimulateSudoAbuseCapability:
  def test_appends_sudo_command_to_bash_history_node(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateSudoAbuseCapability(vfs, shell, "EAC0005", SimpleNamespace(
      sudo_command="sudo systemctl restart mysql", username="daniel",
    )).execute()

    assert result.success is True
    node = vfs.get_node("/root/.bash_history")
    assert node is not None
    assert "sudo systemctl restart mysql" in node.content

  def test_missing_fields_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateSudoAbuseCapability(vfs, shell, "EAC0005", SimpleNamespace()).execute()
    assert result.success is False


class TestPlantSshAuthorizedKeyCapability:
  def test_plants_key_for_root(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = PlantSshAuthorizedKeyCapability(vfs, shell, "EAC0005", SimpleNamespace(
      user="root", key_comment="deploy@ci-runner-03",
    )).execute()

    assert result.success is True
    node = vfs.get_node("/root/.ssh/authorized_keys")
    assert node is not None
    assert "deploy@ci-runner-03" in node.content

  def test_plants_key_for_non_root_user_under_home(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = PlantSshAuthorizedKeyCapability(vfs, shell, "EAC0005", SimpleNamespace(
      user="daniel", key_comment="jenkins@ci",
    )).execute()

    assert result.success is True
    assert vfs.exists("/home/daniel/.ssh/authorized_keys")

  def test_missing_fields_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = PlantSshAuthorizedKeyCapability(vfs, shell, "EAC0005", SimpleNamespace()).execute()
    assert result.success is False


class TestSimulateFirewallActivityCapability:
  def test_adds_rule_visible_in_ufw_status(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateFirewallActivityCapability(vfs, shell, "EAC0018", SimpleNamespace(
      rule_target="3306/tcp", action="deny",
    )).execute()

    assert result.success is True
    output = shell.execute_command("ufw status")
    assert "3306/tcp" in output
    assert "DENY" in output

  def test_invalid_action_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateFirewallActivityCapability(vfs, shell, "EAC0018", SimpleNamespace(
      rule_target="3306/tcp", action="bogus",
    )).execute()
    assert result.success is False
