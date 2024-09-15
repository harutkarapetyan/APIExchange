from sqlalchemy.orm.session import Session
from database import get_session
from models import models
from fastapi import Depends, status
from fastapi.exceptions import HTTPException


class UserService:
    @classmethod
    def delete_user(cls, user):
        get_session.delete(user)
        get_session.commit()

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def get_user(self, user_id):
        try:
            user = self.session.query(models.User).filter_by(user_id=user_id).first()

        except Exception as error:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=error)
        return user



