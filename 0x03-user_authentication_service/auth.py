#!/usr/bin/env python3
"""Auth"""
from db import DB
from typing import Union
from user import User
import bcrypt
import uuid


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, eml: str, password: str) -> User:
        """Register user"""
        user = self._db._session.query(User).filter(User.email == eml).first()
        if user:
            raise ValueError(f"User {user.email} already exists")
        hashed_password = _hash_password(password)
        new_user = User(hashed_password=hashed_password, email=email)
        self._db._session.add(new_user)
        self._db._session.commit()
        return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates login"""
        try:
            user = self._db.find_user_by(email=email)
        except Exception as e:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> Union[str | None]:
        """creates session"""
        try:
            user = self._db.find_user_by(email=email)
            user.session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=user.session_id)
            return user.session_id
        except Exception as err:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User | None]:
        """Get user from session"""
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception as e:
            return None

    def destroy_session(self, user_id: int):
        """Destroy session"""
        if user_id is None:
            return None
        try:
            user = self._db.find_user_by(id=user_id)
            destroyed = self._db.update_user(user_id, session_id=None)
        except Exception as error:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Resets password"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                user.reset_token = _generate_uuid()
                user = self._db.update_user(user.id, reset_token=reset_token)
                return user.reset_token
        except Exception as error:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """updates password"""
        try:
            ur = self._db.find_user_by(reset_token=reset_token)
            pwd = _hash_password(password)
            self._db.update_user(ur.id, hashed_password=pwd, reset_token=None)
            return None
        except Exception as error:
            raise ValueError


def _generate_uuid() -> str:
    """Generate uuid"""
    return str(uuid.uuid4())


def _hash_password(password: str) -> bytes:
    """hashes password"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
