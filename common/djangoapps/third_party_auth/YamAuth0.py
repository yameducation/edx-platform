#pylint: disable=W0223
"""
    python-social-auth backend for use with IdentityServer3
    docs: https://identityserver.github.io/Documentation/docsv2/endpoints/authorization.html
    docs for adding a new backend to python-social-auth:
    https://python-social-auth.readthedocs.io/en/latest/backends/implementation.html#oauth
"""
from social_core.backends.oauth import BaseOAuth2
from django.utils.functional import cached_property
from social_core.backends.oauth import BaseOAuth2
from jose import jwt

class YamAuth0(BaseOAuth2):
    """Auth0 OAuth authentication backend"""

    name = "auth0-yam-embedd"
    SCOPE_SEPARATOR = " "
    ACCESS_TOKEN_METHOD = "POST"
    EXTRA_DATA = [("picture", "picture")]

    def api_path(self, path=""):
        """Build API path for Auth0 domain"""
        return "https://{domain}/{path}".format(
            domain=self.setting("DOMAIN"), path=path
        )

    def authorization_url(self):
        return self.api_path("authorize")

    def access_token_url(self):
        return self.api_path("oauth/token")

    def get_user_id(self, details, response):
        """Return current user id."""
        return details["user_id"]

    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get("id_token")
        jwks = self.get_json(self.api_path(".well-known/jwks.json"))
        issuer = self.api_path()
        audience = "https://temp.yam-edu.com"  # CLIENT_ID
        payload = jwt.decode(
            id_token, jwks, algorithms=["RS256"], audience=audience, issuer=issuer
        )
        fullname, first_name, last_name = self.get_user_names(payload["name"])
        return {
            "username": payload["nickname"],
            "email": payload["email"],
            "email_verified": payload.get("email_verified", False),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "picture": payload["picture"],
            "user_id": payload["sub"],
        }

    