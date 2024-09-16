#!/usr/bin/env python3
""" Session Auth mechanism """
from api.v1.auth.auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    """ SessionAuth class inherits from Auth """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Method that creates a session_id for a user
        """
        if type(user_id) is not str or user_id is None:
            return None
        else:
            sess_id = str(uuid4())
            self.user_id_by_session_id[sess_id] = user_id
            return sess_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Returns a User ID based on a Session ID """
        if type(session_id) is not str or session_id is None:
            return None
        else:
            return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """ Retruns a User instance based on _my_seesion_id """
        sess_cookie = self.session_cookie(request)
        return User.get(self.user_id_for_session_id(sess_cookie))

    def destroy_session(self, request=None):
        """ Destroys a user session """
        if request is None:
            return False

        sess_id = self.session_cookie(request)
        u_id = self.user_id_for_session_id(sess_id)
        if u_id is None or sess_id is None:
            return False

        if sess_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[sess_id]
            return True
        return False
