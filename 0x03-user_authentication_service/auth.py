#!/usr/bin/env python3
'''auth.py - Authentication module for the Flask app'''

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    '''Returns a hashed password'''
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    '''Returns a string representation of a new UUID'''
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user with the system"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Validate a user login"""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode(
                'utf-8'), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new session for a user"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """Get a user from a session ID"""
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroy a session"""
        if user_id:
            self._db.update_user(user_id, session_id=None)
        else:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token"""
        subject = None
        try:
            subject = self._db.find_user_by(email=email)
        except NoResultFound:
            subject = None
        if subject is None:
            raise ValueError
        else:
            reset_token = _generate_uuid()
            self._db.update_user(subject.id, reset_token=reset_token)
            return reset_token
