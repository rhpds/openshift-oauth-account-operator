from oauthprovider import OAuthProvider

class KeycloakOAuthProvider(OAuthProvider):
    async def remove_account(self, name) -> bool:
        """Remove account from keycloak.
        Return boolean to indicate if account was removed."""
        # FIXME
        raise TemporaryError("Remove account not implemented!")

    async def set_password(self, name: str, password) -> bool:
        """Set password for account in keycloak.
        Return boolean to indicate if password changed."""
        # FIXME
        raise TemporaryError("Set password not implemented!")
