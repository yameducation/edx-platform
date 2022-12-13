"""
Auth0 implementation based on:
https://auth0.com/docs/quickstart/webapp/django/01-login
"""
#from jose import jwt

from social_core.backends.oauth import BaseOAuth2

class YamCustomOAuth2(BaseOAuth2):
    """Auth0 OAuth authentication backend"""

    name = "yamedu"
    SCOPE_SEPARATOR = " "
    ACCESS_TOKEN_METHOD = "POST"
    EXTRA_DATA = [("picture", "picture")]

    def api_path(self, path=""):
        """Build API path for Auth0 domain"""
        return "https://litvak.auth0.com/".format(
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
        audience = self.setting("KEY")  # CLIENT_ID
        payload = {}
        # payload = jwt.decode(
        #     id_token, jwks, algorithms=["RS256"], audience=audience, issuer=issuer
        # )
        #fullname, first_name, last_name = self.get_user_names(payload["name"])
        return {
            "username": "unsure",
            "email": "unsure",
            "email_verified": True,
            "fullname": "fullname",
            "first_name": "first_name",
            "last_name": "last_name",
            "picture": "pic",
            "user_id": "sub",
        }