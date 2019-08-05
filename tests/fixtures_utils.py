# Copyright (C) 2018 inbitcoin s.r.l.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

""" Fixtures for utils module """

from lighter import lighter_pb2 as pb


class FakeMetadatum():
    def __init__(self, key, value):
        self.key = key
        self.value = value


CHANNELS = [
    pb.Channel(local_balance=3111, remote_balance=666,
               local_reserve=29, remote_reserve=666,
               active=1, state=1),
    pb.Channel(local_balance=666, remote_balance=555,
               local_reserve=401, remote_reserve=33,
               active=0, state=1),
    pb.Channel(local_balance=47.3, remote_balance=23.71,
               local_reserve=77, remote_reserve=24,
               active=1, state=1),
   pb.Channel(local_balance=577, remote_balance=2531,
              local_reserve=30, remote_reserve=40,
              active=0, state=0),
]


LISTCHANNELRESPONSE = pb.ListChannelsResponse(channels=CHANNELS)


METADATA = (
    FakeMetadatum(key='macaroon', value='stuff'),
    FakeMetadatum(key='user-agent', value='stuff')
)
