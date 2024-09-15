import datetime

from fastapi.exceptions import HTTPException
from fastapi import status, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from fastapi.security.oauth2 import OAuth2PasswordBearer
from sqlalchemy import func

# SqlAlchemy
from sqlalchemy.orm.session import Session

from passlib.hash import bcrypt
from jose import jwt, JWTError

# Own
from schemas.auth_schemas import UserOut, Token, UserCreate, LoginForm, UserResentEmailVerify
from database import get_session
from models import models

from services.service_email.send import registration_verify


oauth2_schema = OAuth2PasswordBearer(tokenUrl='/user_auth_router/login')

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "3600"
}


def get_current_user(token: str = Depends(oauth2_schema)):
    try:
        current_user = AuthService.verify_token(token)
        return current_user
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="In UserApp/services/auth.py function get_current_user()\n"
                                   "Error occurred while trying to get current user\n"
                                   f"ERR: {err}")


class AuthService:
    @classmethod
    def hash_password(cls, plain_password: str) -> str:
        try:
            hashed_password = bcrypt.hash(plain_password)
            return hashed_password
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function hash_password()\n"
                                       "Error occurred while trying to hash password\n"
                                       f"ERR: {err}")

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str):
        try:
            result = bcrypt.verify(plain_password, hashed_password)
            return result
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function verify_password()\n"
                                       "Error occurred while trying to verify password\n"
                                       f"ERR: {err}")

    @classmethod
    def verify_token(cls, token: str):
        try:
            exception = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Couldn't validate credentials",
                headers={
                    "WWW-Authenticated": 'Bearer'
                }
            )
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function verify_token()\n"
                                       "Error occurred while trying to create HTTPException\n"
                                       f"ERR: {err}")
        try:
            payload = jwt.decode(
                token,
                "secret",
                algorithms=["HS256"]
            )
        except JWTError:
            raise exception

        try:
            user_data = payload.get('user')
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function verify_token()\n"
                                       "Error occurred while trying to get user from payload\n"
                                       f"ERR: {err}")

        try:
            user = UserOut.parse_obj(user_data)
        except ValidationError:
            raise exception

        return user

    @classmethod
    def create_token(cls, user):
        try:
            user_data = UserOut.from_orm(user)
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function create_token()\n"
                                       "Error occurred while trying to do user_data = UserOut.from_orm(user)\n"
                                       f"ERR: {err}")

        try:
            now = datetime.datetime.utcnow()
            payload = {
                "exp": now + datetime.timedelta(minutes=43000),  # max -> 43200
                "user": user_data.dict()
            }
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function create_token()\n"
                                       "Error occurred while trying to make payload\n"
                                       f"ERR: {err}")

        try:
            token = jwt.encode(payload, "secret", algorithm="HS256")
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function create_token()\n"
                                       "Error occurred while trying to create token... jwt.encode(...)\n"
                                       f"ERR: {err}")
        try:
            access_token = Token(access_token=token)
            return access_token
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function create_token()\n"
                                       "Error occurred while trying to create and return Token... Token(token)\n"
                                       f"ERR: {err}")

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: UserCreate):
        try:
            user = self.session.query(models.User).filter_by(username=user_data.username).first()
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function register_new_user()\n"
                                       f"Error occurred while trying to get user by username\n"
                                       f"ERR: {err}")
        if user is not None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=f"username already exists")

        try:
            user = self.session.query(models.User).filter_by(email=user_data.email).first()
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function register_new_user()\n"
                                       f"Error occurred while trying to get user by email\n"
                                       f"ERR: {err}")
        if user is not None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=f"email already exists")

        try:
            user = models.User(
                username=user_data.username,
                email=user_data.email,
                password=self.hash_password(user_data.password)
            )
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function register_new_user()\n"
                                       "Error occurred while trying to create User...models.User(...)\n"
                                       f"ERR: {err}")

        try:
            self.session.add(user)
            self.session.commit()
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function register_new_user()\n"
                                       "Error occurred while trying to add user to db and commit\n"
                                       f"ERR: {err}")
        try:
            registration_verify(user_data.email)
        except Exception as err:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function register_new_user()\n"
                                       "Error occurred while trying to send user email verification mail\n"
                                       f"ERR: {err}")

        return user

    @classmethod
    def resend_email_verification(cls, user_data: UserResentEmailVerify):
        try:
            mails_send.MailSend.send_user_email_verify(user_data.email, user_data.username)
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, "
                                       "function resend_email_verification()\n"
                                       "Error occurred while trying to resend user email verification mail\n"
                                       f"ERR: {err}")

        return "OK"

    def verify_user(self, user_email: str):
        try:
            user = self.session.query(models.User).filter_by(email=user_email).first()
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function verify_user()\n"
                                       f"Error occurred while trying to get user by email '{user_email}'\n"
                                       f"ERR: {err}")

        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="In UserApp/services/auth.py class AuthService, function verify_user()\n"
                                       f"User with email '{user_email}' was not found!")
        try:
            user.is_active = True
            self.session.commit()
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Error while trying to update user is_active!\n"
                                       f"ERR: {err}")

        return user

    def authenticate_user(self, login_data: LoginForm):
        try:
            username_or_email = login_data.username_or_email
            password = login_data.password
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function authenticate_user()\n"
                                       "Error occurred while trying to get email and password from login_data\n"
                                       f"ERR: {err}")
        try:
            user = self.session.query(models.User).filter_by(email=username_or_email).first()
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function authenticate_user()\n"
                                       f"Error occurred while trying to get user by email '{username_or_email}'\n"
                                       f"ERR: {err}")
        if user is None:
            try:
                user = self.session.query(models.User).filter_by(username=username_or_email).first()
            except Exception as err:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                    detail="In UserApp/services/auth.py class AuthService, function authenticate_user()\n"
                                           f"Error occurred while trying to get user by username '{username_or_email}'\n"
                                           f"ERR: {err}")
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                    detail=f"User with username or email '{username_or_email}' was not found!")

        if not user.__dict__.get('is_active'):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Email Verification Required")

        try:
            password_from_db = user.__dict__.get('password')
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function authenticate_user()\n"
                                       f"Error occurred while trying to get a password from user taken from database\n"
                                       f"ERR: {err}")

        if not self.verify_password(password, password_from_db):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Wrong password: '{password}'")

        try:
            access_token = self.create_token(user)
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="In UserApp/services/auth.py class AuthService, function authenticate_user()\n"
                                       f"Error occurred while trying to create token...function create_token(...)\n"
                                       f"ERR: {err}")

        return access_token

