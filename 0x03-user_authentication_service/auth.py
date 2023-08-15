#!/usr/bin/env python3
"""Auth"""
from db import DB
from typing import Union
from user import User
import bcrypt
import uuid


def _hash_password(password: str) -> bytes:
    """this method takes password and return salted hash of the password"""
    return hashpw(password.encode('utf-8'), gensalt())


def _generate_uuid() -> str:
    """this method returns a string representation of a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, eml: str, password: str) -> User:
        """Register user"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates login"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound as e:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> Union[str | None]:
        """creates session"""
        try:
            user = self._db.find_user_by(email=email)
            user.session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=user.session_id)
            return user.session_id
        except NoResultFound as err:
            return

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
        except NoResultFound:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """this method takes reset_token string argument and a password
        string argument and returns None - if user exist, hash the password
        and update the user’s hashed_password field with the new hashed
        password and the reset_token field to None - otherwise, raise
        ValueError"""
        if reset_token is None or password is None:
            return None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        hashed_password = _hash_password(password).decode('utf-8')
        self._db.update_user(user.id, hashed_password=hashed_password,
                             reset_token=None)
