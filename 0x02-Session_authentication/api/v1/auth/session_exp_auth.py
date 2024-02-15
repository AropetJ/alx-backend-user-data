#!/usr/bin/env python3
''' Module of Users views
'''

from flask import request
import os

from .auth import SessionAuth


class SessionExpAuth(SessionAuth):
    ''' SessionExpAuth class
    '''
    def __init__(self):
        ''' init
        '''
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        ''' create session
        '''
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id, 'created_at': self.created_at()
            }
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        ''' user id for session id
        '''
        if session_id is None or type(session_id) is not str:
            return None
        session_dictionary = self.user_id_by_session_id.get(session_id)
        if session_dictionary is None:
            return None
        if self.session_duration <= 0:
            return session_dictionary.get('user_id')
        if 'created_at' not in session_dictionary:
            return None
        if (self.created_at() - session_dictionary.get(
                'created_at')) > self.session_duration:
            return None
        return session_dictionary.get('user_id')
