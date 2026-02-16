from kopf import TemporaryError
from kubernetes_asyncio.client.rest import ApiException

from k8sobject import K8sObject
from operatorruntime import OperatorRuntime

class OAuthProvider(K8sObject):
    api_group = OperatorRuntime.operator_domain
    api_version = OperatorRuntime.operator_version
    kind = "OAuthProvider"
    plural = "oauthproviders"

    cluster_oauth_provider = None

    @classmethod
    async def get(cls):
        """Get cluster oauth provider config."""
        if cls.cluster_oauth_provider is not None:
            return cls.cluster_oauth_provider

        try:
            definition = await cls.fetch_definition('cluster')
            cls.load(definition)
            return cls.cluster_oauth_provider
        except ApiException as exception:
            if exception.status == 404:
                raise TemporaryError("No cluster OAuthProvider found.", delay=60)
            raise

    @classmethod
    def load(cls, definition):
        idp_type = definition['spec']['type']
        if idp_type == 'HTPasswd':
            from htpasswdoauthprovider import HTPasswdOAuthProvider
            subclass = HTPasswdOAuthProvider
        elif idp_type == 'Keycloak':
            from keycloakoauthprovider import KeycloakOAuthProvider
            subclass = KeycloakOAuthProvider
        else:
            raise TemporaryError(
                f"Unknown cluster identity provider type: {idp_type}", 
                delay=60,
            )

        if isinstance(cls.cluster_oauth_provider, subclass):
            cls.cluster_oauth_provider.definition = definition
        cls.cluster_oauth_provider = subclass(definition)
