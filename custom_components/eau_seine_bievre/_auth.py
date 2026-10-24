"""Authentication flow for the Eaux de Marseille / SEMM customer portals.

The portal needs five steps to materialise a working session:

1. GET ``/`` — acquire a session cookie from the WAF.
2. POST ``/Acces/generateToken`` — exchange the static app credentials
   for a short-lived bearer token.
3. POST ``/Utilisateur/authentification`` — exchange user credentials
   and the temp token for the long-lived AEL session token.
4. GET ``/Abonnement/getContratParDefaut/`` — fetch the contract metadata.
5. Plant the ``AEL_CONTEXT`` cookie that the portal expects on every
   subsequent call.

Encapsulated as :class:`PortalAuth`: the session, timeout, target portal
and bearer token are kept on the instance, so each step is a tiny method.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import aiohttp
from yarl import URL

from . import _http
from ._app_bundle import parse_app_credentials
from .const import (
    PROVIDERS,
    PortalEndpoints,
    Provider,
    headers_for,
)
from .exceptions import EauxDeMarseilleApiError, EauxDeMarseilleAuthError

_LOGGER = logging.getLogger(__name__)

#: Essais de connexion en changeant de serveur derrière le répartiteur de charge.
_MAX_NODE_ATTEMPTS = 12


def conversation_id() -> str:
    """One-shot ``ConversationId`` header value."""
    return f"JS-WEB-Netscape-{uuid.uuid4()}"


def _without_body_type(headers: dict[str, str]) -> dict[str, str]:
    """Headers for a GET: no ``Content-Type`` (nothing is sent), like the browser."""
    return {k: v for k, v in headers.items() if k.lower() != "content-type"}


def _is_dns_failure(err: BaseException) -> bool:
    """Detect DNS resolution failures from the connector.

    aiohttp normalises both ``AsyncResolver`` (aiodns/c-ares) and
    ``ThreadedResolver`` (``socket.getaddrinfo``) failures into
    :class:`aiohttp.ClientConnectorDNSError` (added in aiohttp 3.10).
    """
    return isinstance(err, aiohttp.ClientConnectorDNSError)


class PortalAuth:
    """Stateful 5-step authentication flow against the SEM/SEMM portal."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        timeout: aiohttp.ClientTimeout,
        provider: Provider,
        login: str,
        password: str,
    ) -> None:
        self._session = session
        self._timeout = timeout
        self._endpoints: PortalEndpoints = PROVIDERS[provider]
        self._base_headers = headers_for(self._endpoints)
        # User credentials live on the auth helper that actually uses them,
        # rather than being duplicated on the higher-level client.
        self._login = login
        self._password = password
        # Two distinct tokens with very different lifetimes:
        # * ``_app_token`` is the short-lived bearer returned by
        #   ``/Acces/generateToken``; only used to authorise the login POST
        #   in step 3.
        # * ``_ael_token`` is the long-lived AEL session token returned by
        #   the login POST itself; used for every authenticated request from
        #   step 4 onwards.
        # Splitting them keeps the lifecycle obvious and unblocks a future
        # token-caching pass across coordinator polls (#12).
        self._app_token: str | None = None
        self._ael_token: str | None = None
        # App credentials read from the portal bundle (providers without
        # pinned ones), cached for the lifetime of this client.
        self._discovered_app_credentials: tuple[str, str] | None = None

    # ------------------------------------------------------------------
    # State predicates
    # ------------------------------------------------------------------

    @property
    def is_authenticated(self) -> bool:
        """Whether a long-lived AEL session token is currently held."""
        return self._ael_token is not None

    def invalidate(self) -> None:
        """Drop the cached AEL token so the next request re-authenticates.

        The portal's ``aelToken`` and ``AEL_CONTEXT`` cookies are left in
        the jar — they will be overwritten by the next successful login.
        Clearing them eagerly would force a session-cookie re-handshake
        on step 1 of the next auth, which the portal handles fine but is
        unnecessary.
        """
        self._app_token = None
        self._ael_token = None

    # ------------------------------------------------------------------
    # Public flow
    # ------------------------------------------------------------------

    async def authenticate(self) -> None:
        """Run all 5 steps; ``self._ael_token`` holds the AEL session token."""
        for attempt in range(1, _MAX_NODE_ATTEMPTS + 1):
            _LOGGER.info("Authentication: step 1/5 (acquiring session cookie)")
            await self._step_landing()

            _LOGGER.info("Authentication: step 2/5 (generating token)")
            temp_token = await self._step_generate_token()

            try:
                _LOGGER.info("Authentication: step 3/5 (logging in user)")
                ael_token, user_info = await self._step_login(temp_token)
                _LOGGER.info("Authentication: step 4/5 (fetching default contract)")
                contract = await self._step_default_contract()
                break
            except EauxDeMarseilleAuthError as err:
                # Eau Seine & Bièvre (octobre 2026) : un des serveurs derrière le répartiteur
                # F5 répond « Session Inconnue » à toute connexion, même valide, ou refuse le
                # jeton juste émis (« Le token de session a expiré »). Le cookie BIGipServer
                # colle la session à ce serveur : on vide les cookies et on recommence pour
                # tomber sur un serveur sain, que l'on garde ensuite.
                message = str(err).lower()
                retriable = "session inconnue" in message or "token de session a expir" in message
                if not retriable or attempt == _MAX_NODE_ATTEMPTS:
                    raise
                _LOGGER.info(
                    "Serveur du portail défaillant (%s), nouvel essai %d/%d",
                    "session inconnue" if "session inconnue" in message else "jeton refusé",
                    attempt + 1,
                    _MAX_NODE_ATTEMPTS,
                )
                self._ael_token = None
                self._session.cookie_jar.clear()

        _LOGGER.info("Authentication: step 5/5 (setting context cookie)")
        self._step_set_context(contract, user_info, ael_token)

        _LOGGER.info("Authentication successful")

    # ------------------------------------------------------------------
    # Authenticated GET (used by the consumption client after step 5)
    # ------------------------------------------------------------------

    async def get(self, path: str) -> dict[str, Any]:
        """Authenticated GET on a path under the active portal's API base."""
        return await _http.request_with_retry(
            self._session,
            "GET",
            f"{self._endpoints.api_base}{path}",
            timeout=self._timeout,
            headers=_without_body_type(self._headers()),
            allowed_host=self._endpoints.host,
        )

    # ------------------------------------------------------------------
    # Steps (private)
    # ------------------------------------------------------------------

    async def _step_landing(self) -> None:
        self._app_token = None
        self._ael_token = None
        try:
            async with self._session.get(
                f"{self._endpoints.url}/",
                headers=self._base_headers,
                timeout=self._timeout,
                allow_redirects=True,
            ) as response:
                await response.read()
                _LOGGER.debug(
                    "Portal landing page: HTTP %d (final URL: %s)",
                    response.status,
                    response.url,
                )
                if response.status >= 400:
                    raise EauxDeMarseilleApiError(
                        f"Portal returned HTTP {response.status} on landing page "
                        f"(final URL: {response.url})"
                    )
        except (aiohttp.ClientError, TimeoutError) as err:
            if _is_dns_failure(err):
                raise EauxDeMarseilleApiError(
                    f"DNS resolution failed for {self._endpoints.host}. "
                    "Check Home Assistant's DNS configuration "
                    "(Settings -> System -> Network -> Network adapter); "
                    f"underlying error: {err}"
                ) from err
            raise EauxDeMarseilleApiError(f"Failed to reach portal: {err}") from err

    async def _app_credentials(self) -> tuple[str, str]:
        """Static app ``(ClientId, AccessKey)``: pinned, or read from the portal bundle."""
        if self._endpoints.client_id and self._endpoints.access_key:
            return self._endpoints.client_id, self._endpoints.access_key
        if self._discovered_app_credentials is not None:
            return self._discovered_app_credentials
        for path in self._endpoints.bundle_paths:
            try:
                async with self._session.get(
                    f"{self._endpoints.url}{path}",
                    headers={**self._base_headers, "Accept": "*/*"},
                    timeout=self._timeout,
                ) as response:
                    if response.status >= 400:
                        continue
                    found = parse_app_credentials(await response.text())
            except (aiohttp.ClientError, TimeoutError) as err:
                raise EauxDeMarseilleApiError(f"Failed to read portal bundle {path}: {err}") from err
            if found:
                self._discovered_app_credentials = found
                return found
        raise EauxDeMarseilleApiError(
            "Application credentials not found in the portal's JavaScript bundle"
        )

    async def _step_generate_token(self) -> str:
        cid = conversation_id()
        client_id, access_key = await self._app_credentials()
        data = await self._auth_call(
            "POST",
            "/Acces/generateToken",
            extra_headers={"ConversationId": cid, "Token": access_key},
            json_payload={
                "ConversationId": cid,
                "ClientId": client_id,
                "AccessKey": access_key,
            },
            require_field="token",
            error_prefix="Token generation failed",
        )
        token: str = data["token"]
        # Pas de cookie aelToken : « Session inconnue » venait d'un serveur défaillant derrière
        # le répartiteur, pas d'un cookie manquant (voir authenticate).
        return token

    async def _step_login(
        self,
        temp_token: str,
    ) -> tuple[str, dict[str, Any]]:
        # The login POST itself must carry the short-lived app token in
        # the ``token`` header. Once it returns, the AEL session token
        # supersedes it and the app token is no longer useful.
        self._app_token = temp_token
        data = await self._auth_call(
            "POST",
            "/Utilisateur/authentification",
            json_payload={"identifiant": self._login, "motDePasse": self._password},
            require_field="tokenAuthentique",
            error_prefix="Login failed",
        )
        # Some SOMEI portals (Eau Seine & Bièvre) can require a second factor:
        # the response then carries ``isMFA: true`` and ``tokenAuthentique`` is
        # only good for ``Utilisateur/validationMFA`` (code sent by e-mail);
        # every other call answers 401 "Le token de session a expiré".
        _LOGGER.info(
            "Login response: keys=%s isMFA=%s expiration=%s",
            sorted(data),
            data.get("isMFA"),
            data.get("expirationDate") or data.get("ExpirationDate"),
        )
        if data.get("isMFA") is True:
            raise EauxDeMarseilleAuthError(
                "Double authentification requise par le portail : un code a été envoyé "
                "par e-mail (validation par code pas encore prise en charge)"
            )
        ael_token: str = data["tokenAuthentique"]
        user_info: dict[str, Any] = data["utilisateurInfo"]
        self._ael_token = ael_token
        self._app_token = None
        # Pas de cookie aelToken / AEL_CONTEXT : vérifié le 24/10/2026 dans le navigateur, le
        # portail sert les données avec le seul en-tête ``Token`` (sans aucun cookie), et un
        # cookie de contexte reconstruit à la main peut faire refuser la session.
        _LOGGER.debug(
            "Cookies before default contract: %s",
            sorted({c.key for c in self._session.cookie_jar}),
        )
        return ael_token, user_info

    async def _step_default_contract(self) -> dict[str, Any]:
        return await self._auth_call("GET", "/Abonnement/getContratParDefaut/")

    def _step_set_context(
        self,
        contract: dict[str, Any],
        user_info: dict[str, Any],
        ael_token: str,
    ) -> None:
        # Rien à poser (voir _step_login) : le contrat par défaut suffit à valider la session.
        _LOGGER.debug("Default contract fetched: keys=%s", sorted(contract))

    # ------------------------------------------------------------------
    # Helpers (private)
    # ------------------------------------------------------------------

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build the standard request headers, with the bearer token if set.

        Prefers the long-lived AEL token over the short-lived app token —
        both can never be set at the same time in the current flow, but the
        precedence makes the contract explicit for future callers.
        """
        headers = {**self._base_headers, "ConversationId": conversation_id()}
        token = self._ael_token or self._app_token
        if token:
            # Same spelling as the portal's JS (``Token``): the Eau Seine & Bièvre
            # front end (F5 BIG-IP) may match header names case-sensitively.
            headers["Token"] = token
        if extra:
            headers.update(extra)
        return headers

    def _set_cookie(self, name: str, value: str) -> None:
        self._session.cookie_jar.update_cookies(
            {name: value},
            response_url=URL(self._endpoints.url),
        )

    async def _auth_call(
        self,
        method: str,
        path: str,
        *,
        json_payload: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        require_field: str | None = None,
        error_prefix: str = "Request failed",
    ) -> dict[str, Any]:
        """API call mapped to :class:`EauxDeMarseilleAuthError` on failure."""
        _LOGGER.debug(
            "%s %s with headers %s",
            method,
            path,
            sorted(self._headers(extra_headers)),
        )
        try:
            data = await _http.request_with_retry(
                self._session,
                method,
                f"{self._endpoints.api_base}{path}",
                timeout=self._timeout,
                headers=self._headers(extra_headers) if method != "GET" else _without_body_type(self._headers(extra_headers)),
                allowed_host=self._endpoints.host,
                json=json_payload,
            )
        except EauxDeMarseilleApiError as err:
            raise EauxDeMarseilleAuthError(f"{error_prefix}: {err}") from err

        if require_field and (not data or require_field not in data):
            raise EauxDeMarseilleAuthError(
                f"{error_prefix}: missing {require_field!r}; got: {sorted(data)}"
            )
        return data
