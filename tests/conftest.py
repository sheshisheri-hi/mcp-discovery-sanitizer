from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURES


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def clean_discovery() -> dict:
    return load_fixture("clean_discovery.json")


@pytest.fixture
def poisoned_instructions() -> dict:
    return load_fixture("poisoned_instructions.json")


@pytest.fixture
def public_cache_untrusted() -> dict:
    return load_fixture("public_cache_untrusted.json")


@pytest.fixture
def overlong_descriptions() -> dict:
    return load_fixture("overlong_descriptions.json")
