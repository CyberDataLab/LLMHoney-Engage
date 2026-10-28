import pytest

from src.honeyengage.virtual_env.machine_persona import MACHINE_ROLES, NEUTRAL_ROLE, pick_machine_role
from src.honeyengage.virtual_env.vfs import FSDirectory, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import VirtualShell


@pytest.fixture
def vfs():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  return vfs


class TestPickMachineRole:
  def test_forced_role_id_is_honored(self):
    role = pick_machine_role("any-session", forced_role_id="database_server")
    assert role.role_id == "database_server"

  def test_unknown_forced_role_id_falls_back_to_random_choice(self):
    role = pick_machine_role("any-session", forced_role_id="not_a_real_role")
    assert role.role_id in MACHINE_ROLES

  def test_same_seed_and_session_id_picks_the_same_role(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_SEED", "42")
    first = pick_machine_role("session-a")
    second = pick_machine_role("session-a")
    assert first.role_id == second.role_id

  def test_different_session_ids_can_pick_different_roles(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_SEED", "42")
    roles = {pick_machine_role(f"session-{i}").role_id for i in range(20)}
    assert len(roles) > 1


class TestPersonaAblationControl:

  def test_persona_mode_none_returns_neutral_role(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_PERSONA_MODE", "none")
    role = pick_machine_role("any-session")
    assert role.role_id == NEUTRAL_ROLE.role_id

  def test_persona_mode_none_overrides_forced_role_id(self, monkeypatch):
    monkeypatch.setenv("HONEYENGAGE_PERSONA_MODE", "none")
    role = pick_machine_role("any-session", forced_role_id="web_server")
    assert role.role_id == NEUTRAL_ROLE.role_id

  def test_neutral_role_has_no_packages_or_ports(self):
    assert NEUTRAL_ROLE.typical_packages == []
    assert NEUTRAL_ROLE.typical_ports == []

  def test_default_mode_is_not_neutral(self, monkeypatch):
    monkeypatch.delenv("HONEYENGAGE_PERSONA_MODE", raising=False)
    monkeypatch.setenv("HONEYENGAGE_SEED", "7")
    role = pick_machine_role("session-x")
    assert role.role_id in MACHINE_ROLES


class TestVirtualShellPersonaIntegration:
  def test_persona_is_fixed_at_construction(self, vfs):
    shell = VirtualShell(vfs, session_id="s1", persona_role_id="web_server")
    assert shell.persona.role_id == "web_server"

  def test_persona_packages_are_added_to_installed_packages(self, vfs):
    shell = VirtualShell(vfs, session_id="s1", persona_role_id="web_server")
    package_names = {p.name for p in shell.installed_packages}
    assert "apache2" in package_names
    assert "mysql-server" in package_names

  def test_persona_ports_are_visible_in_netstat_from_session_start(self, vfs):
    shell = VirtualShell(vfs, session_id="s1", persona_role_id="web_server")
    output = shell.execute_command("netstat -tuln")
    assert "0.0.0.0:80" in output
    assert "0.0.0.0:3306" in output

  def test_persona_packages_are_queryable_via_dpkg(self, vfs):
    shell = VirtualShell(vfs, session_id="s1", persona_role_id="database_server")
    output = shell.execute_command("dpkg -s postgresql-14")
    assert "14.11-0ubuntu0.22.04.1" in output

  def test_different_roles_have_non_overlapping_persona_packages(self, vfs):
    web_shell = VirtualShell(vfs, session_id="s1", persona_role_id="web_server")
    mail_shell = VirtualShell(vfs, session_id="s2", persona_role_id="mail_relay")
    web_names = {p.name for p in web_shell.installed_packages}
    mail_names = {p.name for p in mail_shell.installed_packages}
    assert "postfix" not in web_names
    assert "apache2" not in mail_names
