"""Auth0 sign-in for bearer-token authentication.

Implements the OAuth 2.0 Authorization Code flow with PKCE: the user signs in
at Auth0 in a browser, Auth0 redirects back to a short-lived HTTP server on
``127.0.0.1``, and the authorization code is exchanged for an access token.
The token is kept in memory only (never written to disk) and is sent to the
Resolwe server as ``Authorization: Bearer <token>`` by
:class:`resdk.resolwe.ResAuth`.

On a machine without a browser (e.g. CI), put a token obtained elsewhere in
the ``RESDK_TOKEN`` environment variable instead.
"""

import base64
import hashlib
import http.server
import os
import secrets
import sys
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from typing import Optional

import requests

#: Environment variable holding a pre-obtained access token.
TOKEN_ENV_VAR = "RESDK_TOKEN"

DEFAULT_AUTH0_DOMAIN = "genialis.us.auth0.com"
DEFAULT_AUDIENCE = "https://api.genialis.com"
DEFAULT_SCOPE = "openid profile email"
#: The port is fixed because the redirect URI must exactly match a callback
#: URL registered in the Auth0 application.
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

        :raises ValueError: if ``RESDK_AUTH0_CLIENT_ID`` is not set.
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
            domain=os.environ.get("RESDK_AUTH0_DOMAIN") or DEFAULT_AUTH0_DOMAIN,
            audience=os.environ.get("RESDK_AUTH0_AUDIENCE") or DEFAULT_AUDIENCE,
            scope=os.environ.get("RESDK_AUTH0_SCOPE") or DEFAULT_SCOPE,
        )


def token_from_env() -> Optional[str]:
    """Return the access token from :data:`TOKEN_ENV_VAR`, or ``None`` if unset."""
    return os.environ.get(TOKEN_ENV_VAR) or None


def get_access_token(settings: Optional[Auth0Settings] = None) -> str:
    """Return an Auth0 access token.

    The token from :data:`TOKEN_ENV_VAR` is used if set; otherwise the user is
    signed in through the browser.

    :param settings: Auth0 settings; read from the environment when omitted.
    """
    token = token_from_env()
    if token:
        return token
    if settings is None:
        settings = Auth0Settings.from_env()
    return _login(settings)


def _login(settings: Auth0Settings) -> str:
    """Sign the user in through the browser and return the access token."""
    # PKCE: the sign-in request carries only the SHA-256 challenge; the verifier
    # is revealed when the code is redeemed, so an intercepted code is useless
    # to anyone else.
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    # Auth0 echoes `state` in the redirect; a callback that does not carry it
    # is rejected below.
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

    # Query parameters of the redirect from Auth0, filled in by the handler.
    callback: dict = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        """Receive the redirect from Auth0."""

        def do_GET(self) -> None:
            """Record the callback query and tell the user to return."""
            url = urllib.parse.urlparse(self.path)
            query = dict(urllib.parse.parse_qsl(url.query))
            if url.path != "/callback" or not ("code" in query or "error" in query):
                self.send_error(404)
                return
            callback.update(query)
            if "code" in query and query.get("state") == state:
                message = "Signed in to Resolwe. You can close this tab."
            else:
                message = "Sign-in failed; see the terminal."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(message.encode())

        def log_message(self, *args: object) -> None:
            """Silence the default request logging."""

    try:
        server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), Handler)
    except OSError as error:
        raise RuntimeError(
            f"Cannot listen on 127.0.0.1:{CALLBACK_PORT} for the Auth0 redirect "
            f"({error}). Stop the program using the port, or set {TOKEN_ENV_VAR} "
            "to an access token obtained elsewhere."
        ) from error

    with server:
        server.timeout = 1  # Return from handle_request() to check the deadline.
        print(
            "Opening the browser to sign in. If it does not open, visit:\n"
            f"{authorize_url}",
            file=sys.stderr,
        )
        webbrowser.open(authorize_url)
        deadline = time.monotonic() + LOGIN_TIMEOUT_SECONDS
        while not callback:
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"No sign-in within {LOGIN_TIMEOUT_SECONDS} s; try again."
                )
            server.handle_request()

    if callback.get("state") != state:
        raise RuntimeError(
            "The sign-in response does not match the request; try again."
        )
    if "error" in callback:
        raise RuntimeError(
            f"Auth0 refused the sign-in: {callback['error']}: "
            f"{callback.get('error_description', '')}"
        )

    response = requests.post(
        f"https://{settings.domain}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": settings.client_id,
            "code": callback["code"],
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
        timeout=30,
    )
    if not response.ok:
        raise RuntimeError(f"Auth0 did not issue a token: {response.text[:300]}")
    return response.json()["access_token"]
