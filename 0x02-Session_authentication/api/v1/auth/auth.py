#!/usr/bin/env python3
""" Authentication module """
import re
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """ Auth-sys Template """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if auth is required
        Returns True if auth is required otherwise False
        """
        if path is not None and excluded_paths is not None:
            for ep in map(lambda e: e.strip(), excluded_paths):
                ptrn = ''
                if ep.endswith('*'):
                    ptrn = '{}.*'.format(ep[:-1])
                elif ep.endswith('/'):
                    ptrn = '{}/*'.format(ep[:-1])
                else:
                    ptrn = '{}/*'.format(ep)

                if re.match(ptrn, path):
                    return False
        return True

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

    def session_cookie(self, request=None):
        """ Returns a cookie value from SESSION_NAME """
        if request is None:
            return None
        sess = request.cookies.get(getenv('SESSION_NAME'))
        return sess
