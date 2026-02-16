from base64 import b64decode, b64encode

import bcrypt

from kopf import TemporaryError
from kubernetes_asyncio.client.rest import ApiException

from oauthprovider import OAuthProvider

from operatorruntime import OperatorRuntime

class HTPasswdOAuthProvider(OAuthProvider):
    @property
    def htpasswd_secret_name(self):
        return self.spec \
            .get('htpasswd', {}) \
            .get('secret', {}) \
            .get('name', 'htpasswd')

    @property
    def htpasswd_secret_namespace(self):
        return self.spec \
            .get('htpasswd', {}) \
            .get('secret', {}) \
            .get('namespace', 'openshift-config')

    async def remove_account(self, name) -> bool:
        """Remove account from htpasswd secret
        Return boolean to indicate if account was removed."""
        while True:
            # Loop until successful or encounter an error other than 409 Conflict
            secret = await self.__get_htpasswd_secret()
            try:
                return await self.__remove_account(secret, name)
            except ApiException as exception:
                if exception.status != 409:
                    raise

    async def set_password(self, name: str, password) -> bool:
        """Set password in htpasswd secret.
        Return boolean to indicate if password changed."""
        while True:
            # Loop until successful or encounter an error other than 409 Conflict
            secret = await self.__get_htpasswd_secret()
            try:
                return await self.__set_password(secret, name, password)
            except ApiException as exception:
                if exception.status != 409:
                    raise

    async def __remove_account(self, secret, name: str) -> bool:
        content = b64decode(secret.data.get('htpasswd')).decode('utf-8')
        lines = []
        removed = False
        for line in content.splitlines():
            if line.startswith(f"{name}:"):
                removed = True
            else:
                lines.append(line)
        secret.data['htpasswd'] = b64encode(
            ("\n".join(lines) + "\n").encode('utf-8')
        ).decode('utf-8')
        await OperatorRuntime.core_v1_api.replace_namespaced_secret(
            name=secret.metadata.name,
            namespace=secret.metadata.namespace,
            body=secret,
        )
        return removed

    async def __set_password(self, secret, name: str, password: str) -> bool:
        content = b64decode(secret.data.get('htpasswd')).decode('utf-8')
        lines = []
        for line in content.splitlines():
            entry, pwhash = line.split(':')
            if entry == name:
                if(
                    pwhash.startswith('$2y$') and
                    bcrypt.checkpw(password.encode('utf-8'), pwhash.replace('$2y$', '$2b$').encode('utf-8'))
                ):
                    return False
            else:
                lines.append(line)
        hashed = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt()
        ).decode('utf-8').replace('$2b$', '$2y$')
        lines.append(f"{name}:{hashed}")
        secret.data['htpasswd'] = b64encode(
            ("\n".join(lines) + "\n").encode('utf-8')
        ).decode('utf-8')
        await OperatorRuntime.core_v1_api.replace_namespaced_secret(
            name=secret.metadata.name,
            namespace=secret.metadata.namespace,
            body=secret,
        )
        return True

    async def __get_htpasswd_secret(self):
        try:
            return await OperatorRuntime.core_v1_api.read_namespaced_secret(
                name=self.htpasswd_secret_name,
                namespace=self.htpasswd_secret_namespace,
            )
        except ApiException as exception:
            if exception.status == 404:
                raise TemporaryError(
                    f"HTPasswd secret not found in {self.htpasswd_secret_namespace}: {self.htpasswd_secret_name}",
                    delay=60
                )
            raise
