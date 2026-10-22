"""UI string translations.

Strings live in ``app/locales/<lang>.json`` as flat ``key → text`` maps with
``{name}`` placeholders. English is the base: keys missing from the selected
language fall back to it. Templates call ``t()``; the same dict is injected
into every page as ``I18N`` for ``tr()`` in ``static/util.js``.
"""
import json
from pathlib import Path

from app.config import settings

_LOCALE_DIR = Path(__file__).parent / "locales"

# Must match Settings.contact_message's default.
_DEFAULT_CONTACT_MESSAGE = "Please request a new link from the person who shared this one."


def load_strings(lang: str) -> dict[str, str]:
    """Return the strings for *lang*, with English filling any gaps."""
    base = json.loads((_LOCALE_DIR / "en.json").read_text(encoding="utf-8"))
    if lang != "en":
        base.update(json.loads((_LOCALE_DIR / f"{lang}.json").read_text(encoding="utf-8")))
    return base


# Pre-computed at import time — env vars require a restart to change.
strings = load_strings(settings.ui_language)


def t(key: str, **kwargs) -> str:
    """Look up a UI string and fill its ``{placeholders}``."""
    text = strings.get(key, key)
    return text.format(**kwargs) if kwargs else text


def contact_message() -> str:
    """The configured contact message, translated if it is still the default."""
    if settings.contact_message == _DEFAULT_CONTACT_MESSAGE:
        return t("guest.contact_default")
    return settings.contact_message
