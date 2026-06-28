"""Defense-in-depth: enforce enterprise on every tool/resource operation.

The token verifier already rejects non-enterprise at connect; this is a second
layer so no operation runs without the role even if a token slips through.
"""

from fastmcp.server.middleware.middleware import Middleware
from src.oidc_auth import require_enterprise


class EnterpriseGate(Middleware):
    async def on_call_tool(self, context, call_next):
        require_enterprise()
        return await call_next(context)

    async def on_list_tools(self, context, call_next):
        require_enterprise()
        return await call_next(context)

    async def on_read_resource(self, context, call_next):
        require_enterprise()
        return await call_next(context)
