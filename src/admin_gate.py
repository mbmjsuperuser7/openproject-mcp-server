"""Defense-in-depth: every tool/list/resource op re-checks grant authorization
(tenant entitlement OR individual connectorAccess). The verifier already gates
connect; this ensures no op runs without authorization."""
from fastmcp.server.middleware.middleware import Middleware
from src.oidc_auth import require_authorized

class EnterpriseGate(Middleware):
    async def on_call_tool(self, context, call_next):
        await require_authorized(); return await call_next(context)
    async def on_list_tools(self, context, call_next):
        await require_authorized(); return await call_next(context)
    async def on_read_resource(self, context, call_next):
        await require_authorized(); return await call_next(context)
