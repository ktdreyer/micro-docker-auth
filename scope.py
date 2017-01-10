# From https://github.com/windj007/docker-token-auth-test/blob/master/auth_server/auth_server/auth_server/views.py

#   Copyright 2017 Roman Suvorov <windj007@gmail.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import re


SCOPE_RE = re.compile(r'^(?P<type>repository):(?P<name>[^:]+)(?::(?P<tag>[^:]))?:(?P<actions>.*)$')
class Scope(object):
    def __init__(self, scope_type, name, tag, actions):
        self.type = scope_type
        self.name = name
        self.tag = tag
        self.actions = actions

    def __repr__(self):
        return 'Scope(%r, %r, %r, %r)' % (self.type,
                                          self.name,
                                          self.tag,
                                          self.actions)

    @classmethod
    def parse(cls, scope_str):
        if isinstance(scope_str, unicode):
            scope_str = scope_str.encode('utf8')
        parsed = SCOPE_RE.match(scope_str.strip().lower())
        return Scope(parsed.group('type'),
                     parsed.group('name'),
                     parsed.group('tag'),
                     parsed.group('actions').split(','))
