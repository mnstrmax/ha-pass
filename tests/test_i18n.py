"""Tests for UI translations (app/i18n.py and app/locales/*.json)."""
import json
import re
from pathlib import Path

import pytest

from app import i18n

ROOT = Path(__file__).parent.parent
LOCALE_DIR = ROOT / "app" / "locales"
LANGUAGES = [p.stem for p in LOCALE_DIR.glob("*.json")]


def _locale(lang: str) -> dict[str, str]:
    return json.loads((LOCALE_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def _placeholders(text: str) -> set[str]:
    return set(re.findall(r"\{(\w+)\}", text))


def _used_keys() -> set[str]:
    """Static string keys passed to t() in templates and tr() in JS."""
    pattern = re.compile(r"""\b(?:t|tr)\(\s*['"]([a-z_]+\.[a-z0-9_]+)['"]""")
    keys = set()
    for path in [*ROOT.glob("templates/*.html"), *ROOT.glob("static/*.js"), *ROOT.glob("app/**/*.py")]:
        keys.update(pattern.findall(path.read_text(encoding="utf-8")))
    return keys


def test_supported_languages_match_locale_files():
    assert sorted(LANGUAGES) == ["de", "en"]


def test_every_used_key_exists_in_english():
    missing = _used_keys() - _locale("en").keys()
    assert not missing


@pytest.mark.parametrize("lang", [lang for lang in LANGUAGES if lang != "en"])
def test_translation_covers_english_keys(lang):
    assert not _locale("en").keys() - _locale(lang).keys()


@pytest.mark.parametrize("lang", [lang for lang in LANGUAGES if lang != "en"])
def test_translation_keeps_placeholders(lang):
    en, other = _locale("en"), _locale(lang)
    for key, text in en.items():
        assert _placeholders(other[key]) == _placeholders(text), key


def test_load_strings_falls_back_to_english(tmp_path, monkeypatch):
    (tmp_path / "en.json").write_text('{"a.one": "One", "a.two": "Two"}', encoding="utf-8")
    (tmp_path / "xx.json").write_text('{"a.one": "Eins"}', encoding="utf-8")
    monkeypatch.setattr(i18n, "_LOCALE_DIR", tmp_path)
    assert i18n.load_strings("xx") == {"a.one": "Eins", "a.two": "Two"}


def test_t_formats_placeholders(monkeypatch):
    monkeypatch.setattr(i18n, "strings", {"x.count": "{n} items"})
    assert i18n.t("x.count", n=3) == "3 items"
    assert i18n.t("x.missing") == "x.missing"


def test_default_contact_message_is_translated(monkeypatch):
    monkeypatch.setattr(i18n, "strings", {"guest.contact_default": "Bitte neu anfragen."})
    monkeypatch.setattr(i18n.settings, "contact_message", i18n._DEFAULT_CONTACT_MESSAGE)
    assert i18n.contact_message() == "Bitte neu anfragen."
    monkeypatch.setattr(i18n.settings, "contact_message", "Call Alex.")
    assert i18n.contact_message() == "Call Alex."


def test_default_contact_message_matches_settings_default():
    from app.config import Settings

    assert Settings.model_fields["contact_message"].default == i18n._DEFAULT_CONTACT_MESSAGE


async def test_admin_dashboard_renders_language(client, mock_ha_client, monkeypatch):
    monkeypatch.setattr(i18n, "strings", i18n.load_strings("de"))
    monkeypatch.setattr(i18n.settings, "ui_language", "de")
    resp = await client.get("/admin/dashboard")
    assert resp.status_code == 200
    assert '<html lang="de"' in resp.text
    assert "Gastzugang erstellen" in resp.text
