from types import SimpleNamespace
from unittest.mock import MagicMock

import src.honeyengage.engage_engine.engage_engine as engage_engine_module
from src.honeyengage.virtual_env.virtual_shell import ProcessData


class DummyParser:
  def __init__(self, *args, **kwargs):
    self.mapper = {}


class DummyConnection:
  def __init__(self, payload):
    self.payload = payload

  def model_dump(self):
    return self.payload


class DummyCapability:
  last_options = None
  required_fields = {}

  def __init__(self, vfs, virtual_shell, eac_id, options):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.eac_id = eac_id
    self.options = options
    DummyCapability.last_options = options

  @classmethod
  def option_fields(cls):
    return cls.required_fields

  def execute(self):
    return SimpleNamespace(success=True, eac_id=self.eac_id, function_name="dummy", message="ok")


class DummyFileCapability(DummyCapability):
  required_fields = {
    "file_path": "Path of the file to modify.",
    "new_content": "Replacement content for the file.",
  }


class DummyNetworkCapability(DummyCapability):
  required_fields = {
    "network_data": "Dictionary with the fake connection data.",
  }


class DummyLLMResponse:
  def __init__(self, content):
    self.choices = [SimpleNamespace(message=SimpleNamespace(content=content))]


class DummyLLMCompletions:
  def __init__(self, content):
    self.content = content
    self.last_request = None

  def create(self, **kwargs):
    self.last_request = kwargs
    return DummyLLMResponse(self.content)


class DummyLLMChat:
  def __init__(self, content):
    self.completions = DummyLLMCompletions(content)


class DummyLLMClient:
  def __init__(self, content):
    self.api_key = "test-key"
    self.chat = DummyLLMChat(content)


def build_engine(monkeypatch, llm_content):
  monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)

  monkeypatch.setattr(
    engage_engine_module.EngageEngine,
    "discover_capabilities",
    lambda self, x: {                  
      "modifyFileContentCapability": DummyFileCapability,
      "injectFakeNetworkConnectionCapability": DummyNetworkCapability,
    },
  )

  vfs = MagicMock()
  virtual_shell = MagicMock()
  virtual_shell.current_user = "root"
  virtual_shell.current_tty = "tty1"
  virtual_shell.process_list = [
    ProcessData(
      user="user",
      pid=974,
      cpu_usage=0.0,
      memory_usage=0.2,
      vsz=8744,
      rss=5488,
      tty="tty1",
      stat="S",
      start_time="15:17",
      time="0:00",
      command="bash",
    )
  ]
  virtual_shell.network_connections = [
    DummyConnection(
      {
        "protocol": "TCP",
        "local_address": "127.0.0.1:8080",
        "remote_address": "192.168.1.1:443",
        "state": "ESTABLISHED",
      }
    )
  ]

  engine = engage_engine_module.EngageEngine(DummyLLMClient(llm_content))
  return engine, vfs, virtual_shell


def test_execute_deception_builds_file_options(monkeypatch):
  engine, vfs, virtual_shell = build_engine(
    monkeypatch,
    '{"file_path": "/tmp/decoy.txt", "new_content": "updated decoy content"}',
  )

  engine.execute_deception("session_12345", "EAC0001", "modifyFileContentCapability", "command", "description", vfs, virtual_shell)

  assert DummyCapability.last_options is not None
  assert DummyCapability.last_options.file_path == "/tmp/decoy.txt"
  assert DummyCapability.last_options.new_content == "updated decoy content"


def test_execute_deception_flattens_nested_file_options(monkeypatch):
  engine, vfs, virtual_shell = build_engine(
    monkeypatch,
    '{"command": {"name": "modify_file_content", "arguments": {"file_path": "/tmp/decoy.txt", "new_content": "updated decoy content"}}}',
  )

  engine.execute_deception("session_12345", "EAC0001", "modifyFileContentCapability", "command", "description", vfs, virtual_shell)

  assert DummyCapability.last_options is not None
  assert DummyCapability.last_options.file_path == "/tmp/decoy.txt"
  assert DummyCapability.last_options.new_content == "updated decoy content"


def test_execute_deception_builds_network_options(monkeypatch):
  engine, vfs, virtual_shell = build_engine(
    monkeypatch,
    '{"network_data": {"protocol": "TCP", "local_address": "127.0.0.1:8080", "remote_address": "192.168.1.1:443", "state": "ESTABLISHED"}}',
  )

  engine.execute_deception("session_12345", "EAC0001", "injectFakeNetworkConnectionCapability", "command", "description", vfs, virtual_shell)

  assert DummyCapability.last_options is not None
  assert DummyCapability.last_options.network_data == {
    "protocol": "TCP",
    "local_address": "127.0.0.1:8080",
    "remote_address": "192.168.1.1:443",
    "state": "ESTABLISHED",
  }


def test_session_rng_is_deterministic_given_same_seed_and_session(monkeypatch):
  engine, _, _ = build_engine(monkeypatch, "{}")
  monkeypatch.setenv("HONEYENGAGE_SEED", "42")

  first_draw = engine._session_rng("session-a").random()
  second_draw = engine._session_rng("session-a").random()

  assert first_draw == second_draw


def test_session_rng_differs_across_sessions_given_same_seed(monkeypatch):
  engine, _, _ = build_engine(monkeypatch, "{}")
  monkeypatch.setenv("HONEYENGAGE_SEED", "42")

  session_a_draw = engine._session_rng("session-a").random()
  session_b_draw = engine._session_rng("session-b").random()

  assert session_a_draw != session_b_draw


def test_session_rng_is_nondeterministic_without_seed(monkeypatch):
  engine, _, _ = build_engine(monkeypatch, "{}")
  monkeypatch.delenv("HONEYENGAGE_SEED", raising=False)

  first_rng = engine._session_rng("session-a")
  second_rng = engine._session_rng("session-a")

  assert first_rng.getstate() != second_rng.getstate()

def test_repeat_deployment_tells_the_generator_to_differ_from_what_it_planted(monkeypatch):
  engine, vfs, virtual_shell = build_engine(
    monkeypatch,
    '{"file_path": "/var/log/nginx-access.log", "new_content": "entry"}',
  )

  prompts = []
  for _ in range(engine._VARIETY_MIN_REDEPLOYS + 1):
    engine.execute_deception("session-1", "EAC0001", "modifyFileContentCapability", "cmd", "desc", vfs, virtual_shell)
    prompts.append(engine.llm_client.chat.completions.last_request["messages"][1]["content"])

  for early_prompt in prompts[:engine._VARIETY_MIN_REDEPLOYS]:
    assert "MUST be clearly different" not in early_prompt

  assert "/var/log/nginx-access.log" in prompts[-1]
  assert "MUST be clearly different" in prompts[-1]


def test_artifact_variety_history_is_scoped_per_session(monkeypatch):
  engine, vfs, virtual_shell = build_engine(
    monkeypatch,
    '{"file_path": "/var/log/nginx-access.log", "new_content": "entry"}',
  )

  for _ in range(engine._VARIETY_MIN_REDEPLOYS + 1):
    engine.execute_deception("session-1", "EAC0001", "modifyFileContentCapability", "cmd", "desc", vfs, virtual_shell)
  engine.execute_deception("session-2", "EAC0001", "modifyFileContentCapability", "cmd", "desc", vfs, virtual_shell)
  other_session_prompt = engine.llm_client.chat.completions.last_request["messages"][1]["content"]

  assert "/var/log/nginx-access.log" not in other_session_prompt


def test_chain_mode_generates_all_artifacts_in_one_cross_referencing_call(monkeypatch):
  monkeypatch.setenv("HONEYENGAGE_COA_MODE", "chain")
  engine, vfs, virtual_shell = build_engine(
    monkeypatch,
    '{"modifyFileContentCapability": {"file_path": "/var/log/backup.log", "new_content": "pid 8891 ran /opt/backup.sh"},'
    ' "injectFakeNetworkConnectionCapability": {"network_data": {"pid": 8891}}}',
  )

  chain = [("EAC0005", "modifyFileContentCapability"), ("EAC0005", "injectFakeNetworkConnectionCapability")]
  engine._active_narrative = "A backup job, its log entry and the connection it holds open"
  options = engine._build_coherent_chain_options(chain, "cmd", "desc", "session-1")

  assert options is not None and len(options) == 2
  prompt = engine.llm_client.chat.completions.last_request["messages"][1]["content"]
  assert "A backup job, its log entry and the connection it holds open" in prompt
  assert "MUST NAME THE SUBJECT LITERALLY" in prompt
  subject = engine._narrative_subject("session-1", engine._active_narrative)
  assert subject in prompt


def test_malformed_coherent_chain_payload_falls_back_instead_of_planting_empties(monkeypatch):
  monkeypatch.setenv("HONEYENGAGE_COA_MODE", "chain")
  engine, vfs, virtual_shell = build_engine(monkeypatch, '{"modifyFileContentCapability": {"file_path": "/tmp/a"}}')

  chain = [("EAC0005", "modifyFileContentCapability"), ("EAC0005", "injectFakeNetworkConnectionCapability")]
  assert engine._build_coherent_chain_options(chain, "cmd", "desc", "session-1") is None


def test_non_chain_modes_generate_options_independently(monkeypatch):
  monkeypatch.setenv("HONEYENGAGE_COA_MODE", "multi_ttp")
  engine, vfs, virtual_shell = build_engine(monkeypatch, '{"file_path": "/tmp/a", "new_content": "x"}')

  engine.execute_deception("session-1", "EAC0005", "modifyFileContentCapability", "cmd", "desc", vfs, virtual_shell)
  prompt = engine.llm_client.chat.completions.last_request["messages"][1]["content"]

  assert "MUST REFERENCE EACH OTHER" not in prompt
  assert "THE STORY THESE ARTIFACTS MUST TELL TOGETHER" not in prompt


def test_narrative_subject_is_stamped_into_chain_artifacts(monkeypatch):
  engine, vfs, virtual_shell = build_engine(monkeypatch, "{}")

  stamped = engine._stamp_narrative_subject(
    {
      "log_path": "/var/log/app.log",
      "process_command": "/usr/sbin/appd",
      "service_name": "appd",
      "content": "Aug  8 03:14 job finished ok",
    },
    "backup-runner",
  )

  assert stamped["log_path"] == "/var/log/backup-runner.log"
  assert stamped["process_command"] == "/usr/sbin/backup-runner"
  assert stamped["service_name"] == "backup-runner"
  assert stamped["content"] == "Aug  8 03:14 job finished ok"


def test_narrative_subject_is_stable_per_scenario_and_session(monkeypatch):
  engine, vfs, virtual_shell = build_engine(monkeypatch, "{}")

  a = engine._narrative_subject("session-1", "A backup job and its log")
  b = engine._narrative_subject("session-1", "A backup job and its log")

  assert a == b, "one scenario must keep one subject while it is deployed"
  assert a in engine._NARRATIVE_SUBJECTS

  subjects = {
    engine._narrative_subject("session-1", f"scenario {i}") for i in range(12)
  }
  assert len(subjects) > 1
