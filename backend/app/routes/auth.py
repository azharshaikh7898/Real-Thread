from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
import uuid

from app.core.config import get_settings
from app.core.security import create_access_token, get_current_user, verify_password
from app.db import get_database
from app.dependencies import rate_limit_dependency
from app.schemas import LoginRequest, TokenResponse, UserProfile

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(rate_limit_dependency("login", 10, 60))])
async def login(payload: LoginRequest, request: Request, database = Depends(get_database)) -> TokenResponse:
    user = await database["users"].find_one({"username": payload.username})
    
    # Log failed login attempts
    if not user or not verify_password(payload.password, user["password_hash"]):
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Create a security event for failed login
        failed_login_log = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow(),
            "received_at": datetime.utcnow(),
            "source": "auth",
            "host": "auth-service",
            "event_type": "auth",
            "event_kind": "failed_login",
            "message": f"Failed login attempt for user '{payload.username}' from {client_ip}",
            "severity": "warning",
            "status_code": None,
            "username": payload.username,
            "src_ip": client_ip,
            "user_agent": request.headers.get("user-agent"),
            "metadata": {"reason": "invalid_credentials"},
            "detected_threats": [],
            "actor": {"id": "system", "username": "system", "role": "system"}
        }
        
        # Insert the failed login event into logs
        await database["logs"].insert_one(failed_login_log)
        
        # Try to trigger threat detection if monitoring service is available
        try:
            service = request.app.state.monitoring_service
            await service.ingest_log(database, failed_login_log, {"id": "system", "username": "system", "role": "system"})
        except:
            pass  # Silent fail if service not available
        
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    settings = get_settings()
    token = create_access_token(user["username"], user["role"], settings.access_token_expire_minutes)
    return TokenResponse(access_token=token, role=user["role"], username=user["username"])


@router.get("/me", response_model=UserProfile)
async def me(current_user = Depends(get_current_user)) -> UserProfile:
    return UserProfile(
        id=current_user.get("id", current_user.get("_id")),
        username=current_user["username"],
        role=current_user["role"],
        is_active=current_user.get("is_active", True),
    )
