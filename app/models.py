from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

from flask_login import UserMixin

from app.main import db_session


Base = declarative_base()
Base.query = db_session.query_property()


class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    sub = Column(String(256))
    username = Column(String(256))
    name = Column(String(256))
    email = Column(String(256))
