#!/bin/bash
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

NAME='lighter'

# Absolute script path
if [ "`uname`" = "Linux" ]; then
    PROG="$(readlink -f "$0")"
else
    PROG="$(python -c "import os; print(os.path.realpath('"$0"'))")"
fi

# Environment path
ENV=${ENV:-~/.virtualenvs/lighter-env}

# Server code and data directories
L_DIR='lighter'
L_DATA='lighter-data'

# Docker variables
export APP_DIR='/srv/app' ENV_DIR='/srv/env'

# Highlighting colors
NO_COLOR='\033[m'
OK_COLOR='\033[0;32m'
ERROR_COLOR='\033[0;31m'
OK_STRING='[OK]'
ERROR_STRING='[ERROR]'

# Eclair variables
ECL_REF=${ECL_REF:-'v0.2-beta9'}
ECL_URL='https://raw.githubusercontent.com/ACINQ/eclair'

# Lnd variables
LND_REF=${LND_REF:-'v0.5.2-beta'}
LND_URL='https://raw.githubusercontent.com/lightningnetwork/lnd'
GOOGLEAPIS_URL='https://github.com/googleapis/googleapis/archive'
GOOGLEAPIS_CMT=${GOOGLEAPIS_CMT:-'fe2e48159095b7a7dead65a8657b6c236b6b7548'}

# Setting passed parameters
called_function=$1
shift
params=$*


_die() {
	echo "$@"
	exit 2
}

_check_result() {
	# Checks result and outputs given message
	[ -n "$2" ] && printf "%s " "$2"
	if [ "$1" -ne 0 ]; then
		printf "%b" "${ERROR_COLOR}${ERROR_STRING}${NO_COLOR}\n"
		exit 1
	else
		printf "%b" "${OK_COLOR}${OK_STRING}${NO_COLOR}\n"
	fi
}

check_deps() {
	# Checks if given dependencies are installed
	for dep in $params; do
		which $dep > /dev/null
		_check_result $? "Checking dependency $dep..."
	done
}

_init_venv() {
	# Creates virtualenv if it doesn't already exist
	if [ ! -d "$ENV" ]; then
		virtualenv -p python3 "$ENV"
		if [ $? -ne 0 ]; then
			clean_venv
			virtualenv -p python3 "$ENV"
		fi
		_check_result $? "Virtualenv creation in $ENV..."
	fi
}

_install_pips() {
	pip install -q $params || \
		_die "Installation of pips failed (hint: run 'make clean')"
	_check_result $? "Pip requirements..."
}

setup_common() {
	# Activates virtualenv after its creation and installs required pips
	_init_venv
	. "$ENV/bin/activate"
	$PROG _install_pips $params
}

setup_eclair() {
	# Downloads correct version of eclair-cli and makes it executable
	cd "$L_DIR"
	curl -s -o eclair-cli "$ECL_URL/$ECL_REF/eclair-core/eclair-cli"
	chmod +x eclair-cli
	cd - > /dev/null
}

setup_lnd() {
	# Downloads rpc.proto and googleapis, which are needed by lnd
	. "$ENV/bin/activate"
	$PROG _install_pips $params
	cd $L_DIR
	curl -s -o rpc.proto "$LND_URL/$LND_REF/lnrpc/rpc.proto"
	_check_result $? "Lnd's rpc.proto download..."
	curl -s -L -O "$GOOGLEAPIS_URL/$GOOGLEAPIS_CMT.zip"
	_check_result $? "Googleapis download..."
	unzip -q \
		"$GOOGLEAPIS_CMT.zip" \
		"googleapis-$GOOGLEAPIS_CMT/google/*"
	_check_result $? "Googleapis unzip..."
	rm -rf google; \
		mv "googleapis-$GOOGLEAPIS_CMT/google" .; \
		rm -r "googleapis-$GOOGLEAPIS_CMT"
	_check_result $? "Googleapis renaming..."
	rm "$GOOGLEAPIS_CMT.zip"
	_check_result $? "Googleapis zip removing..."
	cd - > /dev/null
}

build_common() {
	# Generates python modules from lighter.proto
	. "$ENV/bin/activate"
	python -m grpc_tools.protoc \
		--proto_path=. \
		--python_out=. \
		--grpc_python_out=. \
		"$L_DIR/lighter.proto"
	_check_result $? "Building lighter.proto..."
}

build_lnd() {
	# Generates python modules from lnd's proto file (rpc.proto)
	. "$ENV/bin/activate"
	python -m grpc_tools.protoc \
		--proto_path=. \
		-I "$L_DIR" \
		--python_out=. \
		--grpc_python_out=. \
		"$L_DIR/rpc.proto"
	_check_result $? "Building rpc.proto..."
}

_get_tag_arch() {
	case $(arch) in
		x86_64 ) export tag_arch="amd64" ;;
		armv7l ) export tag_arch="arm32v7" ;;
		*      ) _die "Your architecture may be unsupported" ;;
	esac
}

create_dockerfiles() {
	export version="$1"
	shift && export tags_archs="$*"
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	cd docker
	python3 generate_dockerfiles.py
	cd - > /dev/null
}

docker_build() {
	export dock_repo="$1" version="$2" tag_arch="$3"
	[ "$tag_arch" = "" ] && _get_tag_arch
	dockerfile="docker/Dockerfile.$tag_arch" && tag="${dock_repo}:${version}"
	echo "Building docker image for $tag_arch..."
	CMD=$(echo docker build -f "$dockerfile" -t "$tag" .)
	echo "> $CMD" && eval $CMD
}

run() {
	export config_file="$1" VERSION="$2"
	if ! [ -r "$config_file" ]; then
		echo "Cannot find config file"
		cp $L_DATA/config.sample "$config_file" || \
			_die "Cannot initialize config file"
		echo "Starting with example config file"
	fi
	_parse_config
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	if [ "$DOCKER" = "0" ]; then
		# Local building
		mkdir -p "$LOGS_DIR" || _die "Cannot create $LOGS_DIR"
		[ -w "$LOGS_DIR" ] || _die "Cannot write to $LOGS_DIR"
		python3 main.py $VERSION
	else
		# Docker building
		_check_compose
		python3 docker/generate_compose.py
		VERSION=$VERSION docker-compose -f compose.yml up -d $NAME
	fi
}

_check_compose() {
	if ! which docker-compose > /dev/null; then
		$PROG _install_pips docker-compose
	fi
}

stop() {
	. "$ENV/bin/activate"
	_check_compose
	docker-compose -f compose.yml stop $NAME
	docker-compose -f compose.yml rm -fv $NAME
}

logs() {
	. "$ENV/bin/activate"
	_check_compose
	docker-compose -f compose.yml logs -f $NAME
}

clean_venv() {
	rm -rf "$ENV"
}

_parse_config() {
	# Exports all variables in config file, setting defaults where necessary
	set -a
	. "$config_file"
	set +a
	[ -z "$IMPLEMENTATION" ] && _die "'IMPLEMENTATION' variable is necessary"
	export IMPLEMENTATION="$(echo $IMPLEMENTATION |tr '[:upper:]' '[:lower:]')"
	case $IMPLEMENTATION in
		clightning|eclair|lnd ) echo "You chose to use $IMPLEMENTATION" ;;
		* ) _die "Unsupported implementation" ;;
	esac
	set_defaults
}

set_defaults() {
	[ -z "$DOCKER" ] && export DOCKER="1"
	[ -z "$SERVER_KEY" ] && export SERVER_KEY="./$L_DATA/certs/server.key"
	[ -z "$SERVER_CRT" ] && export SERVER_CRT="./$L_DATA/certs/server.crt"
	[ -z "$LOGS_DIR" ] && export LOGS_DIR="./$L_DATA/logs"
	[ -z "$CL_CLI" ] && export CL_CLI="lightning-cli"
	[ -z "$CL_RPC" ] && export CL_RPC="lightning-rpc"
	[ -z "$ECL_HOST" ] && export ECL_HOST="localhost"
	[ -z "$ECL_PORT" ] && export ECL_PORT="8080"
	[ -z "$LND_HOST" ] && export LND_HOST="localhost"
	[ -z "$LND_PORT" ] && export LND_PORT="10009"
	[ -z "$LND_CERT" ] && export LND_CERT="tls.cert"
	[ -z "$LND_MACAROON" ] && export LND_MACAROON="admin.macaroon"
}

lint_code() {
	export dock_tag="$1"
	docker run --rm \
		-v `pwd`/$L_DIR/errors.py:$APP_DIR/$L_DIR/errors.py:ro \
		-v `pwd`/$L_DIR/light_clightning.py:$APP_DIR/$L_DIR/light_clightning.py:ro \
		-v `pwd`/$L_DIR/light_eclair.py:$APP_DIR/$L_DIR/light_eclair.py:ro \
		-v `pwd`/$L_DIR/light_lnd.py:$APP_DIR/$L_DIR/light_lnd.py:ro \
		-v `pwd`/$L_DIR/lighter.py:$APP_DIR/$L_DIR/lighter.py:ro \
		-v `pwd`/$L_DIR/utils.py:$APP_DIR/$L_DIR/utils.py:ro \
		-v `pwd`/$L_DIR/settings.py:$APP_DIR/$L_DIR/settings.py:ro \
		-v `pwd`/tests:$APP_DIR/tests:ro \
		-v `pwd`/reports:$APP_DIR/reports:rw \
		-v `pwd`/.pylintrc:$APP_DIR/.pylintrc:ro \
		--entrypoint $APP_DIR/reports/lint.sh \
		$dock_tag \
		$NAME
}

test_code() {
	export dock_tag="$1"
	rm -rf tests/__pycache__ $L_DIR/__pycache__
	docker run --rm \
		-v `pwd`/$L_DIR/errors.py:$APP_DIR/$L_DIR/errors.py:ro \
		-v `pwd`/$L_DIR/light_clightning.py:$APP_DIR/$L_DIR/light_clightning.py:ro \
		-v `pwd`/$L_DIR/light_eclair.py:$APP_DIR/$L_DIR/light_eclair.py:ro \
		-v `pwd`/$L_DIR/light_lnd.py:$APP_DIR/$L_DIR/light_lnd.py:ro \
		-v `pwd`/$L_DIR/lighter.py:$APP_DIR/$L_DIR/lighter.py:ro \
		-v `pwd`/$L_DIR/utils.py:$APP_DIR/$L_DIR/utils.py:ro \
		-v `pwd`/$L_DIR/settings.py:$APP_DIR/$L_DIR/settings.py:ro \
		-v `pwd`/tests:$APP_DIR/tests:ro \
		-v `pwd`/.coveragerc:$APP_DIR/.coveragerc:ro \
		--entrypoint $ENV_DIR/bin/pytest \
		$dock_tag \
		-v --cov=$L_DIR --cov-report=term-missing
}

# Calls the set called function with the set params passed as a single word
if [ -z "$params" ]; then
	$called_function
else
	$called_function $params
fi
