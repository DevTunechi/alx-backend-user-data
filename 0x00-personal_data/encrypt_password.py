#!/usr/bin/env python3
""" Password encryption using bcrypt """
import bcrypt


def hash_password(password: str) -> bytes:
    """ hash a password using bcrypt """
    gen_salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), gen_salt)
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
     """ Validates if a hashed pwd matches the provided pwd """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
