from __future__ import annotations

import pathlib

import yaml

DEFAULT_RULES = pathlib.Path(__file__).resolve().parents[2] / "config" / "rules.yaml"


def load_rules(path=None) -> dict:
    """Load the rubric-to-rules configuration (YAML)."""
    p = pathlib.Path(path) if path else DEFAULT_RULES
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
