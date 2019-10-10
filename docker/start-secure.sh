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
docker_bash_env
set_defaults
set +a

# Sets ownership
[ -z "$MYUID" ] || usermod -u "$MYUID" "$USER"
chown -R --silent "$USER" "$APP_DIR"

[ "$IMPLEMENTATION" = "lnd" ] && set_lnd_mac /srv/lnd/tmp/lnd.macaroon

# Applies migrations
gosu "$USER" python3 -c 'from migrate import migrate; migrate()'

# Starts secure
if [ $? -eq 0 ]; then
    exec gosu $USER python3 -c 'from secure import secure; secure()'
fi
