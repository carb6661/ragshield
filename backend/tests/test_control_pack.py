import json

import pytest

from app.core.rules import load_control_pack


def valid_control():
    return {
        "id": "TEST-001",
        "title": "Test control",
        "category": "Integrity",
        "severity": "medium",
        "description": "A deterministic extension control.",
        "prompt": "Return a grounded answer.",
        "expected_markers": ["source"],
        "forbidden_markers": ["fabricated"],
        "mitigation": "Require citations.",
        "owasp_mapping": "OWASP LLM09",
    }


def test_load_control_pack(tmp_path):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps({"controls": [valid_control()]}), encoding="utf-8")
    controls = load_control_pack(path)
    assert controls[0].id == "TEST-001"
    assert controls[0].expected_markers == ("source",)


def test_duplicate_identifiers_are_rejected(tmp_path):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps({"controls": [valid_control(), valid_control()]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        load_control_pack(path)


def test_non_json_pack_is_rejected(tmp_path):
    path = tmp_path / "controls.yaml"
    path.write_text("controls: []", encoding="utf-8")
    with pytest.raises(ValueError, match=".json"):
        load_control_pack(path)
