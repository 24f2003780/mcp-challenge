
import hashlib
import contextvars

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

EMAIL = "24f2003780@ds.study.iitm.ac.in"
challenge_var = contextvars.ContextVar("challenge", default=None)

security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        "mcp-challenge-wau0.onrender.com",
        "mcp-challenge-wau0.onrender.com:*",
    ],
)

mcp = FastMCP(
    "Exam Challenge",
    stateless_http=True,
    json_response=True,
    transport_security=security,
)


@mcp.tool()
def solve_challenge() -> str:
    """Return the hash for the current exam challenge header."""
    challenge = challenge_var.get()

    if not challenge:
        raise ValueError("Missing X-Exam-Challenge")

    value = f"{challenge}:{EMAIL.strip().lower()}"
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class HeaderMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        token = challenge_var.set(
            headers.get("x-exam-challenge")
        )

        try:
            await self.app(scope, receive, send)
        finally:
            challenge_var.reset(token)


app = HeaderMiddleware(mcp.streamable_http_app())
