#!/usr/bin/env python3
""" Session Expiration system """
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth
from os import getenv


class SessionExpAuth(SessionAuth):
    """ SessionExpAuth class inherits from SessionAuth """
    def __init__(self):
        """ Construct the SessionExpAuth """
        super().__init__()
        self.session_duration = 0
        try:
            self.session_duration = int(getenv('SESSION_DURATION', 0))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """ Creates a session ID with and expiration """
        sess_id = super().create_session(user_id)
        if sess_id is None:
            return None

        self.user_id_by_session_id[sess_id] = {
                "user_id": user_id,
                "created_at": datetime.now()
        }
        return sess_id

    def user_id_for_session_id(self, session_id=None):
        """
        Return the user_id with sess_id
        """
        if session_id is None:
            return None

        sess_dt = self.user_id_by_session_id.get(session_id)
        if sess_dt is None:
            return None

        if self.session_duration <= 0:
            return sess_dt.get("user_id")

        created_at = sess_dt.get("created_at")
        if created_at is None:
            return None

        expiry_time = timedelta(seconds=self.session_duration)
        if datetime.now() - created_at > expiry_time:
            del self.user_id_by_session_id[session_id]
            return None

        return sess_dt.get("user_id")
