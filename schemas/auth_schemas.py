from pydantic import BaseModel, EmailStr


class BaseUser(BaseModel):
    username: str
    email: EmailStr


class UserCreate(BaseUser):
    password: str

    class Config:
        from_attributes = True


class UserOut(BaseUser):
    user_id: int

    class Config:
        from_attributes = True


class User(BaseUser):
    user_id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'

    class Config:
        from_attributes = True


class LoginForm(BaseModel):
    username_or_email: str
    password: str


class UserResentEmailVerify(BaseModel):
    username: str
    email: EmailStr
