from types import SimpleNamespace

import pytest

from src.honeyengage.engage_engine.capabilities.diversity_and_baseline_capabilities import (
  InjectFakeApplicationCapability,
  InjectFakeNetworkDeviceCapability,
  IntroduceVulnerablePackageCapability,
  ResetToBaselineCapability,
  SimulateMalwareDetonationCapability,
)
from src.honeyengage.virtual_env.vfs import FSDirectory, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)
  return vfs, shell


class TestInjectFakeApplicationCapability:
  def test_adds_matching_package_and_process(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    baseline_packages = len(shell.installed_packages)
    baseline_processes = len(shell.process_list)

    capability = InjectFakeApplicationCapability(vfs, shell, "EAC0006", SimpleNamespace(
      package_name="redis-server", package_version="6.0.16-1ubuntu0.2",
      package_description="Persistent key-value database",
      process_command="/usr/bin/redis-server 127.0.0.1:6379", process_pid=2500,
    ))
    result = capability.execute()

    assert result.success is True
    assert len(shell.installed_packages) == baseline_packages + 1
    assert len(shell.process_list) == baseline_processes + 1
    assert any(p.name == "redis-server" for p in shell.installed_packages)
    assert any(p.pid == 2500 for p in shell.process_list)

  def test_missing_required_fields_fails_without_mutating_state(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    baseline_packages = len(shell.installed_packages)

    result = InjectFakeApplicationCapability(vfs, shell, "EAC0006", SimpleNamespace()).execute()

    assert result.success is False
    assert len(shell.installed_packages) == baseline_packages


class TestInjectFakeNetworkDeviceCapability:
  def test_adds_interface_visible_in_ip_addr(self, vfs_and_shell):
    vfs, shell = vfs_and_shell

    capability = InjectFakeNetworkDeviceCapability(vfs, shell, "EAC0007", SimpleNamespace(
      interface_name="docker0", mac_address="02:42:ac:11:00:01", ipv4_address="172.17.0.1/16",
    ))
    result = capability.execute()

    assert result.success is True
    output = shell.execute_command("ip addr")
    assert "docker0" in output
    assert "172.17.0.1/16" in output

  def test_missing_required_fields_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = InjectFakeNetworkDeviceCapability(vfs, shell, "EAC0007", SimpleNamespace()).execute()
    assert result.success is False


class TestSimulateMalwareDetonationCapability:
  def test_injects_process_and_log_line(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    baseline_processes = len(shell.process_list)

    capability = SimulateMalwareDetonationCapability(vfs, shell, "EAC0013", SimpleNamespace(
      process_command="/tmp/update.sh", process_pid=4000,
      log_line="Jul 17 17:55:01 ubuntu CRON[4000]: (root) CMD (/tmp/update.sh)",
    ))
    result = capability.execute()

    assert result.success is True
    assert len(shell.process_list) == baseline_processes + 1
    assert any(p.pid == 4000 and p.command == "/tmp/update.sh" for p in shell.process_list)
    assert b"CRON[4000]" in vfs.file_contents("/var/log/syslog")

  def test_works_without_optional_log_line(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateMalwareDetonationCapability(vfs, shell, "EAC0013", SimpleNamespace(
      process_command="/tmp/x.sh",
    )).execute()
    assert result.success is True

  def test_missing_process_command_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = SimulateMalwareDetonationCapability(vfs, shell, "EAC0013", SimpleNamespace()).execute()
    assert result.success is False


class TestIntroduceVulnerablePackageCapability:
  def test_adds_vulnerable_package_queryable_via_dpkg(self, vfs_and_shell):
    vfs, shell = vfs_and_shell

    capability = IntroduceVulnerablePackageCapability(vfs, shell, "EAC0023", SimpleNamespace(
      package_name="openssl", vulnerable_version="1.1.1f-1ubuntu2.16",
      package_description="Secure Sockets Layer toolkit",
    ))
    result = capability.execute()

    assert result.success is True
    output = shell.execute_command("dpkg -s openssl")
    assert "1.1.1f-1ubuntu2.16" in output

  def test_missing_required_fields_fails(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    result = IntroduceVulnerablePackageCapability(vfs, shell, "EAC0023", SimpleNamespace()).execute()
    assert result.success is False


class TestResetToBaselineCapability:
  def test_removes_every_injected_artifact_but_keeps_the_original_baseline(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    baseline_processes = len(shell.process_list)
    baseline_connections = len(shell.network_connections)
    baseline_packages = len(shell.installed_packages)

    InjectFakeApplicationCapability(vfs, shell, "EAC0006", SimpleNamespace(
      package_name="redis-server", process_command="/usr/bin/redis-server",
    )).execute()
    InjectFakeNetworkDeviceCapability(vfs, shell, "EAC0007", SimpleNamespace(
      interface_name="docker0", ipv4_address="172.17.0.1/16",
    )).execute()
    IntroduceVulnerablePackageCapability(vfs, shell, "EAC0023", SimpleNamespace(
      package_name="openssl", vulnerable_version="1.1.1f-1ubuntu2.16",
    )).execute()

    assert len(shell.process_list) > baseline_processes
    assert len(shell.installed_packages) > baseline_packages
    assert len(shell.extra_network_interfaces) > 0

    result = ResetToBaselineCapability(vfs, shell, "EAC0019", SimpleNamespace()).execute()

    assert result.success is True
    assert len(shell.process_list) == baseline_processes
    assert len(shell.network_connections) == baseline_connections
    assert len(shell.installed_packages) == baseline_packages
    assert len(shell.extra_network_interfaces) == 0

  def test_reports_how_many_artifacts_were_removed(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    InjectFakeApplicationCapability(vfs, shell, "EAC0006", SimpleNamespace(
      package_name="redis-server", process_command="/usr/bin/redis-server",
    )).execute()

    result = ResetToBaselineCapability(vfs, shell, "EAC0019", SimpleNamespace()).execute()

    assert "removed" in result.message

  def test_is_a_no_op_when_nothing_was_injected(self, vfs_and_shell):
    vfs, shell = vfs_and_shell
    baseline_processes = len(shell.process_list)

    result = ResetToBaselineCapability(vfs, shell, "EAC0019", SimpleNamespace()).execute()

    assert result.success is True
    assert len(shell.process_list) == baseline_processes
