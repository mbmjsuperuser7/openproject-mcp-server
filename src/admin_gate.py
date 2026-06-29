"""Two-layer authorization on every tool/resource operation:

1. enterprise role  — Keycloak says this is an enterprise (non-personal) user.
2. grant entitlement — grant.prvis.com says this user's TENANT (email domain)
   is licensed for the feature (projects). KC authenticates; grant authorizes.

The token verifier already blocks non-enterprise at connect; this is the
tenant-entitlement gate (and defense-in-depth for the role).
"""

from fastmcp.server.middleware.middleware import Middleware
from src.oidc_auth import require_enterprise, caller_email
from src.grant_check import is_entitled


async def _gate():
    require_enterprise()  # raises if not enterprise
    email = caller_email()
    if not await is_entitled(email):
        raise PermissionError(
            "Tenant is not entitled to OpenProject (projects). "
            "A prvis global admin must grant this entitlement."
        )


class EnterpriseGate(Middleware):
    async def on_call_tool(self, context, call_next):
        await _gate()
        return await call_next(context)

    async def on_list_tools(self, context, call_next):
        await _gate()
        return await call_next(context)

    async def on_read_resource(self, context, call_next):
        await _gate()
        return await call_next(context)
