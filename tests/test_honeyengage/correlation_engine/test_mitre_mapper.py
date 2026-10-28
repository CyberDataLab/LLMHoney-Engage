from unittest.mock import MagicMock, patch

from src.honeyengage.correlation_engine.mitre_mapper import MitreMapper, MitreMappingError


@patch("src.honeyengage.correlation_engine.mitre_mapper.MitreMapping")
def test_evaluate_command(mock_mitre_mapping_class):
  mock_llm_client = MagicMock()
  mock_response = MagicMock()
  mock_choice = MagicMock()
  mock_choice.message.content = '{"technique_id": "T1033", "confidence": 0.95, "cti_sentence": "Test sentence"}'
  mock_response.choices = [mock_choice]
  mock_llm_client.chat.completions.create.return_value = mock_response

  mock_instance = MagicMock()
  mock_instance.technique_id = "T1033"
  mock_instance.confidence = 0.95
  mock_instance.cti_sentence = "Test sentence"
  
  mock_instance.model_dump.return_value = {
    "mock model dump": True
  }
  mock_mitre_mapping_class.return_value = mock_instance

  mapper = MitreMapper(llm_client=mock_llm_client, llm_model="dummy-model", attack_data_keys=["T1033"])
  mapping = mapper.evaluate_command("whoami", [])
  
  assert not isinstance(mapping, MitreMappingError)
  assert mapping.technique_id == "T1033"
  assert mapping.confidence == 0.95