"""OIDC (Keycloak) auth for the OpenProject MCP server.

KC authenticates. Authorization = grant.prvis.com decision:
  - the caller's email DOMAIN is an entitled tenant for the feature, OR
  - the caller's EMAIL is individually allowed (connectorAccess, set by a
    global_admin in the identity admin Users tab).
Rejected at TOKEN VERIFICATION (connect-time) if neither holds.
"""

import os, asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from src.grant_check import is_entitled

def _issuer() -> str:
    iss = os.getenv("OIDC_ISSUER")
    if iss: return iss.rstrip("/")
    return os.environ["OIDC_CONFIG_URL"].split("/.well-known/")[0].rstrip("/")

def _jwks_uri() -> str:
    j = os.getenv("OIDC_JWKS_URI")
    return j if j else f"{_issuer()}/protocol/openid-connect/certs"

def _email_of(token) -> str:
    claims = getattr(token, "claims", {}) or {}
    return (claims.get("email") or "").lower().strip()


class GrantVerifier(JWTVerifier):
    """Validate the KC token, then require a grant authorization for the caller."""
    async def verify_token(self, token: str):
        result = await super().verify_token(token)
        if result is None:
            return None
        email = _email_of(result)
        try:
            if not await is_entitled(email):
                return None   # neither tenant-entitled nor individually allowed
        except Exception:
            return None       # fail closed
        return result


def build_auth() -> OIDCProxy:
    verifier = GrantVerifier(jwks_uri=_jwks_uri(), issuer=_issuer(), audience=None)
    return OIDCProxy(
        config_url=os.environ["OIDC_CONFIG_URL"],
        client_id=os.getenv("MCP_CLIENT_ID", "openproject-mcp"),
        client_secret=os.environ["MCP_CLIENT_SECRET"],
        base_url=os.environ["MCP_BASE_URL"],
        token_verifier=verifier,
        token_endpoint_auth_method="client_secret_basic",
        require_authorization_consent=False,
        extra_authorize_params={"kc_idp_hint": os.getenv("MCP_IDP_HINT", "google")},
    )


def caller_email() -> str | None:
    from fastmcp.server.dependencies import get_access_token
    tok = get_access_token()
    return _email_of(tok) if tok is not None else None


async def require_authorized() -> None:
    email = caller_email()
    if not email or not await is_entitled(email):
        raise PermissionError("Not authorized for OpenProject (no tenant entitlement or individual access).")
