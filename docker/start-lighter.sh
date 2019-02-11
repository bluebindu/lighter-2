#!/usr/bin/env bash
#
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

# Activates virtual environment
. "$ENV/bin/activate"

# Exports variables so they are available to python
# Overrides cofiguration variables for docker environment
set -a
. "$APP_DIR/lighter-data/config"
. "$APP_DIR/unix_make.sh"

LOGS_DIR="$APP_DIR/lighter-data/logs"
SERVER_KEY="$APP_DIR/lighter-data/certs/server.key"
SERVER_CRT="$APP_DIR/lighter-data/certs/server.crt"

CL_RPC_DIR="/srv/clightning/.lightning"
CL_CLI_DIR="/srv/clightning/cli"

LND_CERT_DIR="/srv/lnd/certs"
[ -n "$LND_MACAROON_DIR" ] && LND_MACAROON_DIR="/srv/lnd/macaroons"

set_defaults
set +a

# Sets ownership (do not mount host log dir lest chown breaks log file perms)
chown -R --silent $USER "$APP_DIR"

# Starts lighter
exec gosu $USER python3 -u main.py $VERSION
