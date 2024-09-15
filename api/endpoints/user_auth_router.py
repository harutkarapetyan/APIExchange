
# FastAPI
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from services.auth.auth import AuthService
from sqlalchemy.orm import Session

from database import get_session
from models import models

# Own
from schemas.auth_schemas import (
    UserCreate,
    UserOut,
    Token,
    LoginForm,
    UserResentEmailVerify
)


router = APIRouter(
    prefix='/auth',
    tags=["User Auth"]
)


@router.post("/sign-up", response_model=UserOut)
def sign_up(user_data: UserCreate,
            service: AuthService = Depends()):

    return service.register_new_user(user_data)


@router.post("/login", response_model=Token)
def login(login_data: LoginForm,
          service: AuthService = Depends()):

    return service.authenticate_user(login_data)


