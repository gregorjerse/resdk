"""Auth0 sign-in for bearer-token authentication.

Uses the OAuth 2.0 Authorization Code flow with PKCE: the user signs in at
Auth0 in a browser, which redirects to a short-lived HTTP server on
``127.0.0.1``. The resulting access token is returned to the caller and kept in
memory only (never written to disk), like the session cookies obtained by the
interactive login.

The token is then sent to the Resolwe server as ``Authorization: Bearer
<token>`` (see :class:`resdk.resolwe.ResAuth`).
"""

import base64
import hashlib
import http.server
import logging
import os
import secrets
import sys
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

#: Environment variable holding a pre-obtained access token (for machines
#: without a browser, e.g. CI).
TOKEN_ENV_VAR = "RESDK_TOKEN"

DEFAULT_AUTH0_DOMAIN = "genialis.us.auth0.com"
DEFAULT_AUDIENCE = "https://api.genialis.com"
DEFAULT_SCOPE = "openid profile email"
#: The loopback port must match a callback URL registered in the Auth0
#: application.
CALLBACK_PORT = 8484
REDIRECT_URI = f"http://127.0.0.1:{CALLBACK_PORT}/callback"
LOGIN_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Auth0Settings:
    """Auth0 tenant, client and API audience."""

    client_id: str
    domain: str = DEFAULT_AUTH0_DOMAIN
    audience: str = DEFAULT_AUDIENCE
    scope: str = DEFAULT_SCOPE

    @classmethod
    def from_env(cls) -> "Auth0Settings":
        """Build settings from the ``RESDK_AUTH0_*`` environment variables.

        :raises ValueError: if the client id is not configured.
        """
        client_id = os.environ.get("RESDK_AUTH0_CLIENT_ID")
        if not client_id:
            raise ValueError(
                "Auth0 sign-in requires a client id. Set RESDK_AUTH0_CLIENT_ID "
                "(and, if needed, RESDK_AUTH0_DOMAIN and RESDK_AUTH0_AUDIENCE), "
                f"or provide an access token in {TOKEN_ENV_VAR}."
            )
        return cls(
            client_id=client_id,
            domain=os.environ.get("RESDK_AUTH0_DOMAIN", DEFAULT_AUTH0_DOMAIN),
            audience=os.environ.get("RESDK_AUTH0_AUDIENCE", DEFAULT_AUDIENCE),
            scope=os.environ.get("RESDK_AUTH0_SCOPE", DEFAULT_SCOPE),
        )


def token_from_env() -> Optional[str]:
    """Return the access token from the environment, if set."""
    return os.environ.get(TOKEN_ENV_VAR) or None


def get_access_token(settings: Optional[Auth0Settings] = None) -> str:
    """Obtain an Auth0 access token.

    If :data:`TOKEN_ENV_VAR` is set, its value is returned unchanged.
    Otherwise, an interactive browser sign-in is performed.

    :param settings: Auth0 settings; read from the environment when omitted.
    :returns: The bearer access token.
    """
    from_env = token_from_env()
    if from_env:
        return from_env
    if settings is None:
        settings = Auth0Settings.from_env()
    token, _ = _login(settings)
    return token


def _login(settings: Auth0Settings) -> tuple:
    """Perform the browser sign-in; return ``(access_token, expires_in)``."""
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(16)
    authorize_url = f"https://{settings.domain}/authorize?" + urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": settings.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": settings.scope,
            "audience": settings.audience,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
    )
    result: dict = {}

    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            query = dict(urllib.parse.parse_qsl(parsed.query))
            if parsed.path != "/callback" or not ({"code", "error"} & set(query)):
                self.send_response(404)
                self.end_headers()
                return
            result.update(query)
            ok = "code" in query and query.get("state") == state
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            message = (
                "Signed in to Resolwe. You can close this tab."
                if ok
                else "Sign-in failed; see the terminal."
            )
            self.wfile.write(message.encode())

        def log_message(self, *args: object) -> None:
            """Silence the default request logging."""

    try:
        server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), Callback)
    except OSError as error:
        raise RuntimeError(
            f"Port {CALLBACK_PORT} on 127.0.0.1 is in use, and Auth0 sign-in needs "
            f"it for the redirect. Stop the program using it, or set {TOKEN_ENV_VAR} "
            "to an access token obtained elsewhere."
        ) from error

    with server:
        server.timeout = 1
        print(
            "Opening the browser to sign in. If it does not open, visit:\n"
            f"{authorize_url}",
            file=sys.stderr,
        )
        webbrowser.open(authorize_url)
        deadline = time.monotonic() + LOGIN_TIMEOUT_SECONDS
        while not result:
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"No sign-in within {LOGIN_TIMEOUT_SECONDS} s; try again."
                )
            server.handle_request()

    if "error" in result:
        raise RuntimeError(
            f"Auth0 refused the sign-in: {result['error']}: "
            f"{result.get('error_description', '')}"
        )
    if result.get("state") != state:
        raise RuntimeError("The sign-in response does not match the request; try again.")

    response = requests.post(
        f"https://{settings.domain}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": settings.client_id,
            "code": result["code"],
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
        timeout=30,
    )
    if not response.ok:
        raise RuntimeError(f"Auth0 did not issue a token: {response.text[:300]}")
    body = response.json()
    return body["access_token"], int(body.get("expires_in", 3600))
