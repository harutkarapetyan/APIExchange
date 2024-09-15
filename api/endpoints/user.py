from fastapi import APIRouter, Depends, HTTPException, status
from services.user import UserService
from services.auth.auth import get_current_user


router = APIRouter(
    prefix='/user',
    tags=["User Methods"]
)


@router.delete("/")
def delete_user(service: UserService = Depends(), current_user=Depends(get_current_user)):
    return service.delete_user(current_user)


