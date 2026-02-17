from base64 import b64decode

from kopfobject import KopfObject
from oauthprovider import OAuthProvider
from operatorruntime import OperatorRuntime

class OAuthAccount(KopfObject):
    api_group = OperatorRuntime.operator_domain
    api_version = OperatorRuntime.operator_version
    kind = 'OAuthAccount'
    plural = 'oauthaccounts'

    @property
    def email(self) -> str:
        return self.spec.get('email', f"{self.username}@example.com")

    @property
    def first_name(self) -> str:
        return self.spec.get('firstName', self.username)

    @property
    def keycloak_id(self) -> str|None:
        return self.status.get('keycloak', {}).get('id')

    @property
    def keycloak_realm(self) -> str|None:
        return self.status_keycloak_realm or self.spec.get('keycloak_realm')

    @property
    def last_name(self) -> str:
        return self.spec.get('lastName', 'Keycloak')

    @property
    def password(self) -> str:
        return b64decode(self.spec['password']).decode('utf-8')

    @property
    def status_keycloak_realm(self) -> str|None:
        return self.status.get('keycloak', {}).get('realm')

    @property
    def status_username(self) -> str|None:
        return self.status.get('username')

    @property
    def username(self) -> str:
        return self.status_username or self.spec.get('username', self.name)

    async def handle_create(self, logger) -> None:
        await self.__set_password(logger)

    async def handle_delete(self, logger) -> None:
        await self.__remove_password(logger)

    async def handle_resume(self, logger) -> None:
        await self.__set_password(logger)

    async def handle_update(self, logger) -> None:
        await self.__set_password(logger)

    async def __remove_password(self, logger) -> None:
        oauth_provider = await OAuthProvider.get()
        changed = await oauth_provider.remove_account(self)
        if changed:
            logger.info("Removed account for %s", self)

    async def __set_password(self, logger) -> None:
        oauth_provider = await OAuthProvider.get()
        synced = False
        try:
            changed = await oauth_provider.set_password(self)
            if changed:
                logger.info("Set password for %s", self)
            synced = True
        finally:
            if self.status.get('synced') != synced:
                await self.merge_patch_status({"synced": synced})
