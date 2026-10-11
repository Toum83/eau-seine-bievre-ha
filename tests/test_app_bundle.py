"""Tests for reading SOMEI app credentials from a portal JS bundle."""

from __future__ import annotations

import importlib.util
from pathlib import Path

# Pure module: loaded directly so the test doesn't need Home Assistant.
_spec = importlib.util.spec_from_file_location(
    "app_bundle",
    Path(__file__).parent.parent / "custom_components" / "eau_seine_bievre" / "_app_bundle.py",
)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
parse_app_credentials = _mod.parse_app_credentials


def test_finds_credentials_in_minified_bundle() -> None:
    js = 'x={AEL_WEBAPI:{ROOT_PATH:"webapi/",DOCUMENT_ROOT:"",WS_APPLICATION_LOGIN:"AEL-TOKEN-TEST-PRD",WS_APPLICATION_PWD:"XX_fake-KEY!"},y:1}'
    assert parse_app_credentials(js) == ("AEL-TOKEN-TEST-PRD", "XX_fake-KEY!")


def test_tolerates_spaces() -> None:
    js = 'WS_APPLICATION_LOGIN : "A" , WS_APPLICATION_PWD : "B"'
    assert parse_app_credentials(js) == ("A", "B")


def test_returns_none_when_absent() -> None:
    assert parse_app_credentials("var a = 1;") is None
