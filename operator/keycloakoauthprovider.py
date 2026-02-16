from base64 import b64decode
from time import time

import asyncio

import aiohttp

from kopf import TemporaryError

from oauthprovider import OAuthProvider
from operatorruntime import OperatorRuntime

class KeycloakOAuthProvider(OAuthProvider):
    class Session:
        @property
        def expires_soon(self):
            return time() > self.start_time + self.expires_in - 10

        def __init__(self):
            self.base_url = None
            self.access_token = None
            self.expires_in = 0
            self.start_time = 0

        async def start(self, base_url, username, password):
            async with aiohttp.ClientSession() as client:
                async with client.post(
                    url=f"{base_url}/realms/master/protocol/openid-connect/token",
                    data={
                        "client_id": "admin-cli",
                        "grant_type": "password",
                        "password": password,
                        "username": username,
                    }
                ) as resp:
                    if resp.status != 200:
                        raise TemporaryError(f"Keycloak admin login failed: {resp.status}")
                    data = await resp.json()
                    self.access_token = data['access_token']
                    self.expires_in = data['expires_in']
                    self.start_time = time()


    def __init__(self, definition):
        super().__init__(definition)
        self.session = self.Session()
        self.lock = asyncio.Lock()

    @property
    def admin_secret_name(self) -> str:
        return self.spec \
            .get('keycloak', {}) \
            .get('adminSecret', {}) \
            .get('name', 'keycloak-initial-admin')

    @property
    def admin_secret_namespace(self) -> str:
        return self.spec \
            .get('keycloak', {}) \
            .get('adminSecret', {}) \
            .get('namespace', 'keycloak')

    @property
    def base_url(self) -> str:
        return self.spec['keycloak']['baseUrl']

    async def __create_user(self, account) -> bool:
        async with aiohttp.ClientSession() as client:
            async with client.post(
                headers={
                    "Authorization": f"Bearer {self.session.access_token}",
                },
                json={
                    "email": account.email,
                    "emailVerified": True,
                    "enabled": True,
                    "firstName": account.first_name,
                    "lastName": account.last_name,
                    "username": account.username,
                },
                url=f"{self.base_url}/admin/realms/{account.keycloak_realm}/users",
            ) as resp:
                if resp.status == 201:
                    return True
                elif resp.status == 409:
                    return False
                raise TemporaryError(f"Error creating user {account.username}: {resp.status}")

    async def __delete_user(self, account, userid) -> None:
        async with aiohttp.ClientSession() as client:
            async with client.delete(
                headers={
                    "Authorization": f"Bearer {self.session.access_token}",
                },
                url=f"{self.base_url}/admin/realms/{account.keycloak_realm}/users/{userid}",
            ) as resp:
                if resp.status not in {204, 404}:
                    raise TemporaryError(f"Error deleting user {account.username}: {resp.status}")

    async def __get_keycloak_admin_credentials(self) -> tuple[str, str]:
        secret = await OperatorRuntime.core_v1_api.read_namespaced_secret(
            name=self.admin_secret_name,
            namespace=self.admin_secret_namespace,
        )
        username = b64decode(secret.data.get('username')).decode('utf-8')
        password = b64decode(secret.data.get('password')).decode('utf-8')
        return username, password

    async def __get_user_id(self, account) -> str|None:
        async with aiohttp.ClientSession() as client:
            async with client.get(
                headers={
                    "Authorization": f"Bearer {self.session.access_token}",
                },
                params={
                    "username": account.username,
                },
                url=f"{self.base_url}/admin/realms/{account.keycloak_realm}/users",
            ) as resp:
                if resp.status != 200:
                    raise TemporaryError(f"Error getting user {account.username}: {resp.status}")
                data = await resp.json()
                if len(data) == 0:
                    return None
                return data[0]['id']

    async def __set_password(self, account, userid) -> None:
        async with aiohttp.ClientSession() as client:
            async with client.put(
                json={
                    "temporary": False,
                    "type": "password",
                    "value": account.password,
                },
                headers={
                    "Authorization": f"Bearer {self.session.access_token}",
                },
                url=f"{self.base_url}/admin/realms/{account.keycloak_realm}/users/{userid}/reset-password",
            ) as resp:
                if resp.status != 204:
                    raise TemporaryError(f"Error setting user {account.username} password: {resp.status}")

    async def __prepare_session(self) -> None:
        """Start or restart session as needed."""
        async with self.lock:
            if self.base_url == self.session.base_url \
            and not self.session.expires_soon:
                return
            username, password = await self.__get_keycloak_admin_credentials()
            await self.session.start(self.base_url, username, password)

    async def remove_account(self, account) -> bool:
        """Remove account from keycloak.
        Return boolean to indicate if account was removed."""
        await self.__prepare_session()
        userid = await self.__get_user_id(account)
        if userid is None:
            return False
        await self.__delete_user(account, userid)

    async def set_password(self, account) -> bool:
        """Set password for account in keycloak.
        Return boolean to indicate if password changed."""
        await self.__prepare_session()
        created = await self.__create_user(account)
        userid = await self.__get_user_id(account)
        await self.__set_password(account, userid)
