#!/usr/bin/env python3
'''Session database authentication module.
'''

from datetime import datetime, timedelta
from flask import request

from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    '''Session database authentication class.
    '''
    def create_session(self, user_id=None):
        '''Create a new session.
        '''
        session_id = super().create_session(user_id)
        if session_id:
            user_session = UserSession(user_id=user_id, session_id=session_id)
            user_session.save()
            return session_id
        return None

    def user_id_for_session_id(self, session_id=None):
        '''Return the user ID for the session ID.
        '''
        if session_id:
            user_session = UserSession.get(session_id)
            if user_session and user_session.created_at + timedelta(
                    seconds=self.session_duration) > datetime.now():
                return user_session.user_id
        return None

    def destroy_session(self, request=None):
        '''Destroy a session.
        '''
        if request:
            session_id = self.session_cookie(request)
            if session_id:
                user_session = UserSession.get(session_id)
                if user_session:
                    user_session.remove()
                    return True
        return False
