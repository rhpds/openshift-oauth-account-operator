import logging 

import kopf

from oauthaccount import OAuthAccount
from oauthprovider import OAuthProvider
from configure_kopf_logging import configure_kopf_logging
from infinite_relative_backoff import InfiniteRelativeBackoff
from operatorruntime import OperatorRuntime

@kopf.on.startup()
async def on_startup(settings: kopf.OperatorSettings, **_):
    # Store last handled configuration in status
    settings.persistence.diffbase_storage = kopf.StatusDiffBaseStorage(
        field='status.diffBase'
    )

    # Never give up from network errors
    settings.networking.error_backoffs = InfiniteRelativeBackoff()

    # Use operator domain as finalizer
    settings.persistence.finalizer = OperatorRuntime.operator_domain

    # Store progress in status.
    settings.persistence.progress_storage = kopf.StatusProgressStorage(
        field='status.kopf'
    )

    # Create events on info and above
    settings.posting.level = logging.INFO

    # Disable scanning for CustomResourceDefinitions updates
    settings.scanning.disabled = True

    # Configure logging to suppress noisy default logging
    configure_kopf_logging()

    await OperatorRuntime.on_startup()

@kopf.on.cleanup()
async def on_cleanup(**_):
    await OperatorRuntime.on_cleanup()

@kopf.on.create(
    OAuthAccount.api_group, OAuthAccount.api_version, OAuthAccount.plural,
)
async def oauth_account_create(logger, **kwargs):
    oauth_account = OAuthAccount(**kwargs)
    await oauth_account.handle_create(logger)

@kopf.on.delete(
    OAuthAccount.api_group, OAuthAccount.api_version, OAuthAccount.plural,
)
async def oauth_account_delete(logger, **kwargs):
    oauth_account = OAuthAccount(**kwargs)
    await oauth_account.handle_delete(logger)

@kopf.on.resume(
    OAuthAccount.api_group, OAuthAccount.api_version, OAuthAccount.plural,
)
async def oauth_account_resume(logger, **kwargs):
    oauth_account = OAuthAccount(**kwargs)
    await oauth_account.handle_resume(logger)

@kopf.on.update(
    OAuthAccount.api_group, OAuthAccount.api_version, OAuthAccount.plural,
)
async def oauth_account_update(logger, **kwargs):
    oauth_account = OAuthAccount(**kwargs)
    await oauth_account.handle_update(logger)

@kopf.on.event(
    OAuthProvider.api_group, OAuthProvider.api_version, OAuthProvider.plural,
)
async def oauth_provider_event(event, logger, **_):
    OAuthProvider.load(event['object'])
