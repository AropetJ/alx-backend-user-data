#!/usr/bin/env python3
"""encrypt password module for encrypting passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using a random salted algorithm.
    Returns:
        bytes: The salted, hashed password, which is a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """validate that the provided password matches the hashed password.
    Returns:
        bool: True if the hashed password matches the given password,
        False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
