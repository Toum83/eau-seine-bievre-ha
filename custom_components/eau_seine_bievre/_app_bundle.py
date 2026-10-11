"""Discover a SOMEI portal's application credentials from its public JS bundle.

Some providers (Eau Seine & Bièvre) don't have their ``ClientId`` /
``AccessKey`` pinned in :mod:`.const`: the portal ships them in its public
Angular bundle (``AEL_WEBAPI.WS_APPLICATION_LOGIN`` / ``WS_APPLICATION_PWD``)
exactly like the other providers, and the browser reads them from there. We do
the same at runtime, which also follows any key rotation by the utility.
These are app-level constants shared by every user, not personal secrets.
"""

from __future__ import annotations

import re

_CREDENTIALS_RE = re.compile(
    r'WS_APPLICATION_LOGIN\s*:\s*"(?P<login>[^"]+)"\s*,\s*WS_APPLICATION_PWD\s*:\s*"(?P<pwd>[^"]+)"'
)


def parse_app_credentials(js: str) -> tuple[str, str] | None:
    """Return ``(client_id, access_key)`` found in a portal bundle, or None."""
    match = _CREDENTIALS_RE.search(js)
    if match is None:
        return None
    return match.group("login"), match.group("pwd")
