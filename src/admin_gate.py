"""Global admin gate middleware.

Every tool call on this server must be made by a Keycloak-authenticated caller
holding the `global_admin` realm role. This is an M2M/admin connector, so the
gate is applied uniformly rather than per-tool.
"""

from fastmcp.server.middleware.middleware import Middleware
from src.oidc_auth import require_admin


class AdminGate(Middleware):
    async def on_call_tool(self, context, call_next):
        require_admin()  # raises PermissionError if role missing
        return await call_next(context)
