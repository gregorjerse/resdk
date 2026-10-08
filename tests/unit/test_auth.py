"""Unit tests for bearer-token / Auth0 authentication."""

import unittest
from unittest.mock import patch

from resdk import auth
from resdk.resolwe import ResAuth


class _Request:
    """Minimal stand-in for a prepared request."""

    def __init__(self):
        self.headers = {}


class TestResAuthBearer(unittest.TestCase):
    def test_bearer_sets_authorization_header(self):
        res_auth = ResAuth(url="http://localhost:8000", token="a.b.c")
        request = res_auth(_Request())
        self.assertEqual(request.headers["Authorization"], "Bearer a.b.c")
        # No CSRF header or cookies are used with bearer auth.
        self.assertNotIn("X-CSRFToken", request.headers)
        self.assertEqual(res_auth.cookies, {})

    def test_anonymous_sets_no_authorization_header(self):
        res_auth = ResAuth(url="http://localhost:8000")
        request = res_auth(_Request())
        self.assertNotIn("Authorization", request.headers)
        self.assertIsNone(res_auth.token)


class TestTokenFromEnv(unittest.TestCase):
    def test_returns_token_when_set(self):
        with patch.dict("os.environ", {auth.TOKEN_ENV_VAR: "tok"}, clear=False):
            self.assertEqual(auth.token_from_env(), "tok")

    def test_returns_none_when_unset(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(auth.token_from_env())


class TestAuth0Settings(unittest.TestCase):
    def test_from_env_requires_client_id(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                auth.Auth0Settings.from_env()

    def test_from_env_reads_overrides(self):
        env = {
            "RESDK_AUTH0_CLIENT_ID": "cid",
            "RESDK_AUTH0_DOMAIN": "example.auth0.com",
            "RESDK_AUTH0_AUDIENCE": "https://api.example",
        }
        with patch.dict("os.environ", env, clear=True):
            settings = auth.Auth0Settings.from_env()
        self.assertEqual(settings.client_id, "cid")
        self.assertEqual(settings.domain, "example.auth0.com")
        self.assertEqual(settings.audience, "https://api.example")


class TestGetAccessToken(unittest.TestCase):
    def test_returns_env_token_without_browser(self):
        # When RESDK_TOKEN is set, no interactive sign-in is attempted.
        with patch.dict("os.environ", {auth.TOKEN_ENV_VAR: "env-token"}, clear=True):
            with patch.object(auth, "_login") as login_mock:
                self.assertEqual(auth.get_access_token(), "env-token")
                login_mock.assert_not_called()

    def test_interactive_login_used_without_env_token(self):
        settings = auth.Auth0Settings(client_id="cid")
        with patch.dict("os.environ", {}, clear=True):
            with patch.object(auth, "_login", return_value=("signed-token", 3600)) as m:
                self.assertEqual(auth.get_access_token(settings), "signed-token")
                m.assert_called_once_with(settings)


if __name__ == "__main__":
    unittest.main()
