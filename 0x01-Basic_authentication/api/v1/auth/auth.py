#!/usr/bin/env python3
''' Module of Auth views
'''
import re
from flask import request
from typing import List, TypeVar


class Auth:
    '''Auth class
    '''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        ''' require_auth method
        '''
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        ''' authorization_header method
        '''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        ''' current_user method
        '''
        return None
