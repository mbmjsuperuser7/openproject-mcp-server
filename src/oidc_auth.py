"""OIDC (Keycloak) auth for the OpenProject MCP server.

Access is restricted to ENTERPRISE accounts. Enforcement happens at TOKEN
VERIFICATION (i.e. at connect): a Keycloak token without the `enterprise`
realm role is rejected, so a personal/non-tenant account cannot complete the
OAuth connection at all — not merely blocked at tool-call time.

Enterprise accounts in prvis only exist when a global_admin has provisioned the
tenant/entitlement, so this role is the correct tenant gate.

Env:
  OIDC_CONFIG_URL    https://sso.prvis.com/sso/realms/prvis/.well-known/openid-configuration
  OIDC_ISSUER        https://sso.prvis.com/sso/realms/prvis
  OIDC_JWKS_URI      https://sso.prvis.com/sso/realms/prvis/protocol/openid-connect/certs
  MCP_CLIENT_ID      openproject-mcp
  MCP_CLIENT_SECRET  <kc client secret>
  MCP_BASE_URL       https://mcp.prvis.com
  MCP_REQUIRED_ROLE  realm role required (default: enterprise)
"""

import os
from urllib.parse import urlparse
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.auth.oidc_proxy import OIDCProxy

REQUIRED_ROLE = os.getenv("MCP_REQUIRED_ROLE", "enterprise")


def _issuer() -> str:
    iss = os.getenv("OIDC_ISSUER")
    if iss:
        return iss.rstrip("/")
    # derive from config_url (.../realms/prvis/.well-known/openid-configuration)
    cfg = os.environ["OIDC_CONFIG_URL"]
    return cfg.split("/.well-known/")[0].rstrip("/")


def _jwks_uri() -> str:
    j = os.getenv("OIDC_JWKS_URI")
    return j if j else f"{_issuer()}/protocol/openid-connect/certs"


def _roles_of(token) -> list[str]:
    claims = getattr(token, "claims", {}) or {}
    return (claims.get("realm_access") or {}).get("roles") or []


class EnterpriseJWTVerifier(JWTVerifier):
    """JWTVerifier that additionally requires the `enterprise` realm role.

    Rejecting here means the OIDCProxy/connector never accepts the token, so a
    non-enterprise user fails at connect, not at tool execution.
    """
    async def verify_token(self, token: str):
        result = await super().verify_token(token)
        if result is None:
            return None
        if REQUIRED_ROLE not in _roles_of(result):
            return None  # not enterprise -> reject the token entirely
        return result


def build_auth() -> OIDCProxy:
    verifier = EnterpriseJWTVerifier(
        jwks_uri=_jwks_uri(),
        issuer=_issuer(),
        audience=None,          # KC aud varies; role check is the gate
    )
    return OIDCProxy(
        config_url=os.environ["OIDC_CONFIG_URL"],
        client_id=os.getenv("MCP_CLIENT_ID", "openproject-mcp"),
        client_secret=os.environ["MCP_CLIENT_SECRET"],
        base_url=os.environ["MCP_BASE_URL"],
        token_verifier=verifier,
        token_endpoint_auth_method="client_secret_basic",
    )


def caller_roles() -> list[str]:
    from fastmcp.server.dependencies import get_access_token
    tok = get_access_token()
    return _roles_of(tok) if tok is not None else []


def require_enterprise() -> None:
    if REQUIRED_ROLE not in caller_roles():
        raise PermissionError(
            f"Access restricted to '{REQUIRED_ROLE}' (enterprise) accounts."
        )


def caller_email() -> str | None:
    from fastmcp.server.dependencies import get_access_token
    tok = get_access_token()
    if tok is None:
        return None
    claims = getattr(tok, "claims", {}) or {}
    return claims.get("email")
