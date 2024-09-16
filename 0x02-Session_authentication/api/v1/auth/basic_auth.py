#!/usr/bin/env python3
""" Basic Authentication module """
from api.v1.auth.auth import Auth
import base64
import binascii
from typing import TypeVar, Optional, Tuple
from models.user import User
import re


class BasicAuth(Auth):
    """ BasicAuth class inheriting from Auth """
    def extract_base64_authorization_header(self,
                                            authorization_header: str
                                            ) -> Optional[str]:
        """
        Extracts the Base64 part of the Authorization header for basic_auth
        Returns: Base64 or None if header is invalid
        """
        if isinstance(authorization_header, str):
            checker = re.fullmatch(r'^Basic (?P<token>.+)$',
                                   authorization_header.strip())
            return checker.group('token') if checker else None
        return None

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> Optional[str]:
        """
        Decodes the Base64 part of the Auth header
        Returns: decoded value as a string or None if input is invalid
        """
        if isinstance(base64_authorization_header, str):
            try:
                b64 = base64_authorization_header
                decoded_val = base64.b64decode(b64, validate=True)
                return decoded_val.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None
        return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> Tuple[str, str]:
        """
        Extracts user credentials from the decoded Base64 auth header
        Returns: tuple containing user email & password,
                 or None, None if invalid
        """
        if isinstance(decoded_base64_authorization_header, str):
            ptrn = r'(?P<user>[^:]+):(?P<password>.+)'
            b64 = decoded_base64_authorization_header.strip()
            checker = re.fullmatch(ptrn, b64)
            if checker:
                usr = checker.group('user')
                passwd = checker.group('password')
                return usr, passwd
        return None, None

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> Optional[User]:
        """
        Retrieves a user instance based on the usr email and passwd
        Returns: UserType or None otherwise
        """
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({'email': user_email})
                if users and users[0].is_valid_password(user_pwd):
                    return users[0]
            except Exception as e:
                return None
        return None

    def current_user(self, request=None) -> Optional[User]:
        """
        Retrieves current User instance
        """
        if request is None:
            return None

        auth_header = self.authorization_header(request)
        b64_header = self.extract_base64_authorization_header(auth_header)
        decode_header = self.decode_base64_authorization_header(b64_header)
        usr_email, usr_pwd = self.extract_user_credentials(decode_header)
        return self.user_object_from_credentials(usr_email, usr_pwd)
