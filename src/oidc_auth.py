"""OIDC (Keycloak) authentication for the OpenProject MCP server.

Replaces the static MCP_API_KEYS scheme with OAuth against the prvis Keycloak
realm. Claude's custom connector performs the OAuth flow (Dynamic Client
Registration is handled by FastMCP's OIDCProxy); every call must carry a valid
KC access token AND the `global_admin` realm role — this is an M2M/admin
integration, so non-admin logins are rejected.

Env:
  OIDC_CONFIG_URL   e.g. https://sso.prvis.com/sso/realms/prvis/.well-known/openid-configuration
  MCP_CLIENT_ID     KC confidential client id (default: openproject-mcp)
  MCP_CLIENT_SECRET KC client secret
  MCP_BASE_URL      public URL of THIS server, e.g. https://mcp.prvis.com
  MCP_REQUIRED_ROLE realm role required to use the server (default: global_admin)
"""

import os
from fastmcp.server.auth.oidc_proxy import OIDCProxy

REQUIRED_ROLE = os.getenv("MCP_REQUIRED_ROLE", "global_admin")


def build_auth() -> OIDCProxy:
    """Construct the Keycloak-backed OIDC auth provider for FastMCP."""
    config_url = os.environ["OIDC_CONFIG_URL"]
    client_id = os.getenv("MCP_CLIENT_ID", "openproject-mcp")
    client_secret = os.environ["MCP_CLIENT_SECRET"]
    base_url = os.environ["MCP_BASE_URL"]

    return OIDCProxy(
        config_url=config_url,
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        # KC tokens are confidential-client; basic is the KC default.
        token_endpoint_auth_method="client_secret_basic",
    )


def caller_roles() -> list[str]:
    """Realm roles on the current request's KC token (empty if unauthenticated)."""
    from fastmcp.server.dependencies import get_access_token

    tok = get_access_token()
    if tok is None:
        return []
    claims = getattr(tok, "claims", {}) or {}
    realm_access = claims.get("realm_access") or {}
    return realm_access.get("roles") or []


def require_admin() -> None:
    """Raise unless the caller carries the required (global_admin) realm role.

    Call at the top of every tool that mutates OpenProject. M2M connector
    integrations are admin-only by policy.
    """
    if REQUIRED_ROLE not in caller_roles():
        raise PermissionError(
            f"This connector is restricted to '{REQUIRED_ROLE}'. "
            "Your account does not have that role."
        )
