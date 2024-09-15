from fastapi import APIRouter

from .endpoints.user_auth_router import router as user_auth_router
from .endpoints.user import router as user_router
from .endpoints.crypto import router as cripto

router = APIRouter(
    prefix='/api'
)


router.include_router(user_auth_router)
router.include_router(user_router)
router.include_router(cripto)

