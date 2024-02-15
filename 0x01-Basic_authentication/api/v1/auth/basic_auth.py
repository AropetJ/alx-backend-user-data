#!/usr/bin/env python3
''' Module of Auth views
'''
import base64
import binascii
from .auth import Auth


class BasicAuth(Auth):
    '''BasicAuth class
    '''
    def extract_base64_authorization_header(self,
                                            authorization_header: str
                                            ) -> str:
        ''' extract_base64_authorization_header method
        '''
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        ''' decode_base64_authorization_header method
        '''
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        ''' extract_user_credentials method
        '''
        if decoded_base64_authorization_header is None:
            return (None, None)
        if type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(':', 1))
