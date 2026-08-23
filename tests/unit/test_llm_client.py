from __future__ import annotations

from morphiq.llm_client import LLMClient


def test_prompt_uses_current_model_fields(config_factory, log_entry):
    client = LLMClient(config_factory())

    prompt = client.build_prompt(log_entry, [], [], [])

    assert "Query: user=admin" in prompt
    assert "Status: 401" in prompt


def test_parse_assessment_accepts_fenced_json(config_factory):
    client = LLMClient(config_factory())

    assessment = client.parse_assessment(
        '```json\n{"threat_label":"sqli","confidence":1.2,'
        '"recommended_action":"block","ban_duration_seconds":60,'
        '"reasoning":"payload matched"}\n```'
    )

    assert assessment is not None
    assert assessment.confidence == 1.0
    assert assessment.recommended_action == "block"
