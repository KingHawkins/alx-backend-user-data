#!/usr/bin/env python3
"""
DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import InvalidRequestError, NoResultFound
from sqlalchemy.orm import sessionmaker
# from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from typing import Mapping

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db")
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds user
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Filters users by id"""
        if kwargs:
            pattern = list(kwargs.keys())
            if not hasattr(User, pattern[0]):
                raise InvalidRequestError
            user = (self._session.query(User)
                    .filter(getattr(User, pattern[0]) == kwargs[pattern[0]])
                    .first())
            if user is None:
                raise NoResultFound
            return user
        raise InvalidRequestError

    def update_user(self, user_id: int, **kwargs: Mapping) -> None:
        """Updates user"""
        try:
            user = self.find_user_by(id=user_id)
            for key, value in kwargs.items():
                setattr(user, key, value)
            self._session.add(user)
            self._session.commit()
            return None
        except InvalidRequestError as e:
            raise ValueError
