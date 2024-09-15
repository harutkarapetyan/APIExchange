from sqlalchemy import Column, Integer, String, Boolean, text, ForeignKey, Float
from sqlalchemy.sql.sqltypes import TIMESTAMP
from database import Base


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, nullable=False, primary_key=True)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    status = Column(Boolean, nullable=True, server_default="False")
    phone = Column(String, nullable=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("now()"))


class Card(Base):
    __tablename__ = "cards"

    card_id = Column(Integer, nullable=False, primary_key=True)
    card_number = Column(Integer, nullable=False)
    card_valid_thru = Column(String, nullable=False)  # "MM/YYYY"
    card_name = Column(String, nullable=False)
    card_cvv = Column(Integer, nullable=False)
    user_id = Column(Integer, ForeignKey("users.user_id"))




