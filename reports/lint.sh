#!/bin/sh
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

REPORTS="$(dirname $0)"
PROGRAMNAME="$(basename $0)"

PROJECTNAME="$1"
PERSIST="--persistent=y"

PWD=$(pwd)

ENV_BIN=''
[ -n "${ENV}" ] && ENV_BIN="${ENV}/bin/"

usage () {
    echo "Usage: ${PROGRAMNAME} app [--persist]" 1>&2
}

if [ -z "${PROJECTNAME}" ]; then
    usage
    exit 1
fi

# Override exit on errors
set +e

echo "Running pycodestyle..."
ignore="*_pb2*.py,cliter.py,secure.py,env.py,*_add_secret_type_column.py"
${ENV_BIN}pycodestyle --exclude=$ignore \
	"${PROJECTNAME}" \
	> "${REPORTS}/pycodestyle.report"

echo "Running pylint..."
${ENV_BIN}pylint --ignore-patterns='.*_pb2.*\.py' \
	--rcfile=.pylintrc ${PERSIST} -f parseable \
	"${PROJECTNAME}" \
	> "${REPORTS}/pylint.report"

echo "Linting complete"
