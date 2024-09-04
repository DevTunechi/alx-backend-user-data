#!/usr/bin/env python3
""" Authentication module """
from flask import request
from typing import List, TypeVar
import fnmatch


class Auth:
    """ Auth-sys Template """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if auth is required
        Returns True if auth is required otherwise False
        """
        if path is None or (excluded_paths is None or
                            len(excluded_paths) == 0):
            return True

        normalized_path = path.rstrip('/') + '/'

        for ep in excluded_paths:
            normalized_ep = ep.rstrip('/') + '/'
            if normalized_path == normalized_ep:
                return False

    def authorization_header(self, request=None) -> str:
        """
        Gets the auth header from the request
        Returns None
        """
        if request is None:
            return None

        auth_header = request.headers.get('Authorization')
        return auth_header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Gets current user from request
        Returns None
        """
        return None


def require_auth(self, path: str, excluded_paths: list) -> bool:
    """
    Checks if a path requires authentication based on excluded paths.

    Args:
        path (str): The path to check.
        excluded_paths (list): A list of patterns that don't require auth

    Returns:
        bool: True if authentication is required, False otherwise.
    """
    if not path or not excluded_paths:
        return True

    for pattern in excluded_paths:
        if fnmatch.fnmatch(path, pattern):
            return False

    return True
