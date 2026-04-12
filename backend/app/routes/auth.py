from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import get_settings
from app.core.security import create_access_token, get_current_user, verify_password
from app.db import get_database
from app.dependencies import rate_limit_dependency
from app.schemas import LoginRequest, TokenResponse, UserProfile

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(rate_limit_dependency("login", 10, 60))])
async def login(payload: LoginRequest, database = Depends(get_database)) -> TokenResponse:
    user = await database["users"].find_one({"username": payload.username})
    if not user or not verify_password(payload.password, user["password_hash"]):
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
