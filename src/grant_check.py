"""Grant entitlement enforcement for the OpenProject MCP server.

Keycloak authenticates (verifier already blocks non-enterprise at connect).
Grant authorizes: this module asks grant.prvis.com whether the caller's
tenant (email domain) is entitled to a feature (default: projects). The MCP
authenticates to grant machine-to-machine using its own Keycloak
client-credentials token (the openproject-mcp service account).

Env:
  GRANT_URL         https://grant.prvis.com         (default)
  GRANT_FEATURE     projects                         (default)
  OIDC_ISSUER       https://sso.prvis.com/sso/realms/prvis
  MCP_CLIENT_ID     openproject-mcp
  MCP_CLIENT_SECRET <kc client secret>
"""

import os, time, json, asyncio, urllib.request, urllib.parse, logging

logger = logging.getLogger(__name__)

GRANT_URL = os.getenv("GRANT_URL", "https://grant.prvis.com").rstrip("/")
FEATURE   = os.getenv("GRANT_FEATURE", "projects")
UA        = "prvis-openproject-mcp"

_token_cache = {"tok": None, "exp": 0.0}
_ent_cache: dict[tuple[str, str], tuple[bool, float]] = {}
_ENT_TTL = 60.0  # seconds


def _issuer() -> str:
    iss = os.getenv("OIDC_ISSUER")
    if iss:
        return iss.rstrip("/")
    cfg = os.environ["OIDC_CONFIG_URL"]
    return cfg.split("/.well-known/")[0].rstrip("/")


def _fetch_m2m_token() -> str:
    """KC client-credentials token for the openproject-mcp service account."""
    now = time.time()
    if _token_cache["tok"] and _token_cache["exp"] > now + 10:
        return _token_cache["tok"]
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": os.getenv("MCP_CLIENT_ID", "openproject-mcp"),
        "client_secret": os.environ["MCP_CLIENT_SECRET"],
    }).encode()
    req = urllib.request.Request(
        _issuer() + "/protocol/openid-connect/token",
        data=data, headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        body = json.loads(r.read().decode())
    tok = body["access_token"]
    _token_cache["tok"] = tok
    _token_cache["exp"] = now + float(body.get("expires_in", 60))
    return tok


def _check_sync(domain: str, feature: str, email: str = "") -> bool:
    key = (domain, feature, email)
    hit = _ent_cache.get(key)
    now = time.time()
    if hit and hit[1] > now:
        return hit[0]
    try:
        tok = _fetch_m2m_token()
        qs = urllib.parse.urlencode({"tenant_id": domain, "feature": feature, "email": email})
        req = urllib.request.Request(
            f"{GRANT_URL}/api/check?{qs}",
            headers={"User-Agent": UA, "Authorization": f"Bearer {tok}"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            body = json.loads(r.read().decode())
        entitled = bool(body.get("entitled"))
    except Exception as e:
        logger.warning("grant check failed for %s/%s: %s", domain, feature, e)
        entitled = False  # fail closed
    _ent_cache[key] = (entitled, now + _ENT_TTL)
    return entitled


async def is_entitled(email: str, feature: str | None = None) -> bool:
    if not email or "@" not in email:
        return False
    domain = email.split("@", 1)[1].lower().strip()
    feat = feature or FEATURE
    return await asyncio.to_thread(_check_sync, domain, feat, email.lower().strip())
