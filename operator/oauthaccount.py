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
    def password(self) -> str:
        return b64decode(self.spec['password']).decode('utf-8')

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
        changed = await oauth_provider.remove_account(self.name)
        if changed:
            logger.info("Removed account for %s", self)

    async def __set_password(self, logger) -> None:
        oauth_provider = await OAuthProvider.get()
        synced = False
        try:
            changed = await oauth_provider.set_password(
                name=self.name,
                password=self.password,
            )
            if changed:
                logger.info("Set password for %s", self)
            synced = True
        finally:
            if self.status.get('synced') != synced:
                await self.merge_patch_status({"synced": synced})
