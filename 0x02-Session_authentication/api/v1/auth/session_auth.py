#!/usr/bin/env python3
''' Module of Users views
'''

from uuid import uuid4
from .auth import Auth


class SessionAuth(Auth):
    ''' SessionAuth class
    '''
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        ''' create session
        '''
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id
    
    def user_id_for_session_id(self, session_id: str = None) -> str:
        ''' user id for session id
        '''
        if session_id is None or type(session_id) is not str:
            return None
        return self.user_id_by_session_id.get(session_id)
