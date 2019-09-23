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

# Starts a bash to command the cli
exec gosu $USER bash
