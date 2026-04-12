from fastapi import Depends, HTTPException, Request, status

from app.core.security import get_current_user


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


def rate_limit_dependency(scope: str, limit: int, window_seconds: int = 60):
    async def dependency(request: Request):
        rate_limiter = request.app.state.rate_limiter
        key = f"{scope}:{get_client_ip(request)}"
        if not rate_limiter.allow(key, limit, window_seconds):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    return dependency


async def current_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
