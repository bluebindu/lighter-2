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
if [ "$(uname)" = "Linux" ]; then
	PROG="$(readlink -f "$0")"
else
	PROG="$(python -c "import os; print(os.path.realpath('"$0"'))")"
fi

# Environment path
export ENV=${ENV:-~/.virtualenvs/lighter-env}

# Cli
CLI_NAME="lit-cli"
COMPLETION_SCRIPT="complete-$CLI_NAME.sh"
TMP_BASHRC='.bashrc_tmp'

# Server code and data directories
L_DIR='lighter'
L_DATA='lighter-data'
LINT_DIR='reports'

# Docker variables
export APP_DIR='/srv/app' ENV_DIR='/srv/env'
COMPOSE=compose.yml
D_DIR='docker'

# Highlighting colors
NO_COLOR='\033[m'
OK_COLOR='\033[0;32m'
ERROR_COLOR='\033[0;31m'
OK_STRING='[OK]'
ERROR_STRING='[ERROR]'

# Eclair variables
ECL_REF=${ECL_REF:-'v0.3.1'}
ECL_URL='https://raw.githubusercontent.com/ACINQ/eclair'
ECL_CLI='eclair-cli'

# Lnd variables
LND_REF=${LND_REF:-'v0.7.1-beta'}
LND_URL='https://raw.githubusercontent.com/lightningnetwork/lnd'
LND_PROTO='rpc.proto'
GOOGLEAPIS_URL='https://github.com/googleapis/googleapis/archive'
GOOGLEAPIS_CMT=${GOOGLEAPIS_CMT:-'fe2e48159095b7a7dead65a8657b6c236b6b7548'}
GOOGLEAPIS_ZIP="$GOOGLEAPIS_CMT.zip"

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
		which "$dep" > /dev/null
		_check_result $? "Checking dependency $dep..."
	done
}

_init_venv() {
	# Creates virtualenv if it doesn't already exist
	if [ ! -d "$ENV" ]; then
		virtualenv -p python3 "$ENV"
		if [ $? -ne 0 ]; then
			_clean_venv
			virtualenv -p python3 "$ENV"
		fi
		_check_result $? "Virtualenv creation in $ENV..."
	fi
}

_install_pips() {
	pip install -q -U pip
	pip install -q $params || \
		_die "Installation of pips failed (hint: run 'make clean')"
	_check_result $? "Pip requirements..."
}

_copy_config() {
	if [ ! -r "$config_file" ]; then
		echo "Cannot find config file"
		cp $L_DATA/config.sample "$config_file" || \
			_die "Cannot initialize config file"
		echo "Starting with example config file"
	fi
}

setup_common() {
	# Activates virtualenv after its creation and installs required pips
	_init_venv
	. "$ENV/bin/activate"
	$PROG _install_pips $params
}

setup_eclair() {
	# Downloads correct version of eclair's cli and makes it executable
	cd "$L_DIR" || _die "Directory '$L_DIR' is missing"
	curl -s -o "$ECL_CLI" "$ECL_URL/$ECL_REF/eclair-core/$ECL_CLI"
	chmod +x "$ECL_CLI"
	cd - > /dev/null || _die "Error, check project structure"
}

setup_lnd() {
	# Downloads rpc.proto and googleapis, which are needed by lnd
	. "$ENV/bin/activate"
	$PROG _install_pips $params
	cd "$L_DIR" || _die "Directory '$L_DIR' is missing"
	curl -s -o "$LND_PROTO" "$LND_URL/$LND_REF/lnrpc/$LND_PROTO"
	_check_result $? "Lnd's proto download..."
	curl -s -L -O "$GOOGLEAPIS_URL/$GOOGLEAPIS_ZIP"
	_check_result $? "Googleapis download..."
	unzip -q \
		"$GOOGLEAPIS_ZIP" \
		"googleapis-$GOOGLEAPIS_CMT/google/api/*"
	_check_result $? "Googleapis unzip..."
	rm -rf google; \
		mv "googleapis-$GOOGLEAPIS_CMT/google" .; \
		rm -r "googleapis-$GOOGLEAPIS_CMT"
	_check_result $? "Googleapis renaming..."
	rm -f "$GOOGLEAPIS_ZIP"
	_check_result $? "Googleapis zip removing..."
	cd - > /dev/null || _die "Error, check project structure"
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
	# Generates python modules from lnd's proto file
	. "$ENV/bin/activate"
	python -m grpc_tools.protoc \
		--proto_path=. \
		-I "$L_DIR" \
		--python_out=. \
		--grpc_python_out=. \
		"$L_DIR/$LND_PROTO"
	_check_result $? "Building lnd's proto..."
}

_get_host_tag_arch() {
	case $(uname) in
		Linux  ) _get_linux_arch ;;
		Darwin ) _get_darwin_arch ;;
		*      ) echo "Your OS may be unsupported" ;;
	esac
	if [ -z "$host_tag_arch" ]; then
		echo "Your architecture may be unsupported"
		export host_tag_arch="amd64"
	fi
}

_get_linux_arch() {
	case $(arch) in
		x86_64 ) export host_tag_arch="amd64" ;;
		armv7l ) export host_tag_arch="arm32v7" ;;
	esac
}

_get_darwin_arch() {
	case $(arch) in
		# "arch" command behaves differently on Mac OS
		i386 ) export host_tag_arch="amd64" ;;
	esac
}

create_dockerfiles() {
	export version="$1"
	shift && export tags_archs="$*"
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	cd "$D_DIR" || _die "Directory '$D_DIR' is missing"
	python3 generate_dockerfiles.py
	cd - > /dev/null || _die "Error, check project structure"
}

docker_build() {
	export dock_repo="$1" version="$2"
	shift 2 && export tags_archs="$*"
	_get_host_tag_arch
	_create_dockerfile
	_docker_build
}

_create_dockerfile() {
	cd "$D_DIR" || _die "Directory '$D_DIR' is missing"
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	python3 generate_dockerfiles.py "$host_tag_arch"
	cd - > /dev/null || _die "Error, check project structure"
}

_docker_build() {
	dockerfile="$D_DIR/Dockerfile.$host_tag_arch" && tag="${dock_repo}:${version}"
	echo "Building docker image for $host_tag_arch..."
	CMD=$(echo docker build -f "$dockerfile" -t "$tag" .)
	echo "> $CMD" && eval "$CMD"
}

run() {
	export config_file="$1" VERSION="$2"
	_parse_config
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	if [ "$DOCKER" = "0" ]; then
		# Local running
		_run_local
	else
		# Docker running
		_run_docker
	fi
}

_run_docker() {
	export MYUID=$(id -u)
	python3 $D_DIR/generate_compose.py
	_check_compose
	docker-compose -f $COMPOSE up -d $NAME
}

_run_local() {
	declare -a dirs=(CERTS_DIR DB_DIR LOGS_DIR MACAROONS_DIR)
	for dir in "${dirs[@]}"; do
		mkdir -p "${!dir}" 2> /dev/null
		[ -w "${!dir}" ] || _die "Cannot create or write to ${!dir}"
	done
	python3 main.py "$VERSION"
}


_check_compose() {
	if ! which docker-compose > /dev/null; then
		$PROG _install_pips docker-compose
	fi
}

secure() {
	export config_file="$1" VERSION="$2"
	_parse_config
	_check_db
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	[ "$IMPLEMENTATION" = "lnd" ] && _init_lnd
	if [ "$DOCKER" = "0" ]; then
		# Local secure
		python3 -c 'from secure import secure; secure()'
	else
		# Docker secure
		python3 $D_DIR/generate_compose.py
		_check_compose
		docker-compose -f $COMPOSE run --rm \
			-e NO_DB="$NO_DB" \
			-e RM_DB="$RM_DB" \
			--entrypoint /usr/local/bin/start-secure.sh \
			$NAME
	fi
}

_check_db() {
	db="$DB_DIR/$DB_NAME"
	[ ! -r "$db" ] && export NO_DB=1 && return
	printf "Db already exists, do you want to override it? (note this will also delete\nmacaroon files) [y/N] "
	read -r res
	res="$(echo "$res" | tr '[:upper:]' '[:lower:]')"
	if [ "${res:0:1}" = 'y' ]; then
		export RM_DB=1
	fi
}

_init_lnd() {
	printf "If your lnd instance requires a macaroon for authorization, provide its path\nhere (filename included, overrides current one if any) or just press enter to\nprovide none (skip)\n"
	read -r macaroon_path
	if [ -n "$macaroon_path" ]; then
		[ ! -f "$macaroon_path" ] && \
			_die "Could not find macaroon in specified path"
		[ ! -r "$macaroon_path" ] && \
			_die "Could not read macaroon in specified path (hint: check file permissions)"
		export LND_MAC="$macaroon_path"
	fi
}

set_lnd_mac() {
	file="$1"
	temp_file="/srv/lnd/macaroons/lnd.macaroon"
	mkdir -p "/srv/lnd/macaroons"
	cp "$file" "$temp_file"
	chown "$USER" "$temp_file"
	chmod 600 "$temp_file"
}

cli() {
	export config_file="$1" VERSION="$2"
	_parse_config
	[ -r "$ENV" ] || _init_venv
	. "$ENV/bin/activate"
	if [ "$DOCKER" = "0" ]; then
		# Local running
		_cli_local
	else
		# Docker running
		_cli_docker
	fi
}

_cli_docker() {
	_check_compose
	docker-compose -f $COMPOSE run --rm \
		--entrypoint /usr/local/bin/start-cli.sh \
		$NAME
}

_cli_local() {
	set_cli
	bash -c ". \$ENV/bin/activate && \
			exec bash --rcfile $TMP_BASHRC"
}

set_cli() {
	! which $CLI_NAME > /dev/null && pip install -q --editable .
	_LIT_CLI_COMPLETE=source $CLI_NAME > $COMPLETION_SCRIPT
	cat ~/.bashrc $COMPLETION_SCRIPT > $TMP_BASHRC
}

stop() {
	. "$ENV/bin/activate"
	_check_compose
	docker-compose -f $COMPOSE stop $NAME
	docker-compose -f $COMPOSE rm -fv $NAME
}

logs() {
	. "$ENV/bin/activate"
	_check_compose
	docker-compose -f $COMPOSE logs -f $NAME
}

clean() {
	_clean_venv
	_clean_autogenerated
}

_clean_venv() {
	rm -rfv "$ENV" | tail -1
}

_clean_autogenerated() {
	# Docker files
	find $D_DIR/ -name 'Dockerfile.*' \
		! -name 'Dockerfile.cross' \
		! -name 'Dockerfile.ci' \
		-type f -delete -printf "removed '%p'\n"
	rm -fv "$COMPOSE"
	# Python files
	find . -name __pycache__ -type d -exec rm -rf "{}" \; \
		-prune -printf "removed directory '%p'\n"
	find . -name .pytest_cache -type d -exec rm -rf "{}" \; \
		-prune -printf "removed directory '%p'\n"
	find . -name '*.pyc' -type f -delete -printf "removed '%p'\n"
	rm -rfv $L_DIR/lighter_pb2*.py
	# Cli files
	rm -rfv "$COMPLETION_SCRIPT" $TMP_BASHRC lit_cli.egg-info
	# Lint files
	rm -fv .coverage "$LINT_DIR/pycodestyle.report" "$LINT_DIR/pylint.report"
	# Eclair files
	rm -fv "$L_DIR/$ECL_CLI"
	# Lnd files
	rm -fv $L_DIR/rpc_pb2*.py "$L_DIR/$LND_PROTO" "$GOOGLEAPIS_ZIP"
	rm -rfv "$L_DIR/google/" | tail -1
}

_parse_config() {
	_copy_config
	# Exports all variables in config file, setting defaults where necessary
	set -a
	. "$config_file"
	set +a
	[ -z "$IMPLEMENTATION" ] && _die "'IMPLEMENTATION' variable is necessary"
	IMPLEMENTATION="$(echo "$IMPLEMENTATION" | tr '[:upper:]' '[:lower:]')"
	export IMPLEMENTATION
	case $IMPLEMENTATION in
		clightning|eclair|lnd ) echo "You chose to use $IMPLEMENTATION" ;;
		* ) _die "Unsupported implementation" ;;
	esac
	set_defaults
}

docker_bash_env() {
	CL_DIR="/srv/clightning"
	LND_DIR="/srv/lnd"
	LOGS_DIR="$APP_DIR/$L_DATA/logs"
	CERTS_DIR="$APP_DIR/$L_DATA/certs"
	SERVER_KEY="$CERTS_DIR/server.key"
	SERVER_CRT="$CERTS_DIR/server.crt"
	MACAROONS_DIR="$APP_DIR/$L_DATA/macaroons"
	DB_DIR="$APP_DIR/$L_DATA/db"
	CLI_HOST="$NAME"
	CL_RPC_DIR="$CL_DIR/.lightning"
	CL_CLI_DIR="$CL_DIR/cli"
	LND_CERT_DIR="$LND_DIR/certs"
	LND_MAC="$LND_DIR/macaroons/lnd.macaroon"
}

set_defaults() {
	[ -z "$DOCKER" ] && export DOCKER="1"
	declare -a vars=(PORT SERVER_KEY SERVER_CRT LOGS_DIR DB_DIR DB_NAME CERTS_DIR
					 MACAROONS_DIR CL_CLI CL_RPC ECL_HOST ECL_PORT LND_HOST
					 LND_PORT LND_CERT CLI_HOST)
	for var_name in "${vars[@]}"; do
		def_val=$(python3 -c "from lighter.settings import $var_name; print($var_name)")
		[ -z "${!var_name}" ] && export ${var_name}="${def_val}"
	done
	[ "$DOCKER" = "1" ] && export CLI_HOST="$NAME"
}

lint_code() {
	export dock_tag="$1"
	docker run --rm \
		-v "$(pwd)/$L_DIR/errors.py:$APP_DIR/$L_DIR/errors.py:ro" \
		-v "$(pwd)/$L_DIR/light_clightning.py:$APP_DIR/$L_DIR/light_clightning.py:ro" \
		-v "$(pwd)/$L_DIR/light_eclair.py:$APP_DIR/$L_DIR/light_eclair.py:ro" \
		-v "$(pwd)/$L_DIR/light_lnd.py:$APP_DIR/$L_DIR/light_lnd.py:ro" \
		-v "$(pwd)/$L_DIR/lighter.py:$APP_DIR/$L_DIR/lighter.py:ro" \
		-v "$(pwd)/$L_DIR/macaroons.py:$APP_DIR/$L_DIR/macaroons.py:ro" \
		-v "$(pwd)/$L_DIR/utils.py:$APP_DIR/$L_DIR/utils.py:ro" \
		-v "$(pwd)/$L_DIR/settings.py:$APP_DIR/$L_DIR/settings.py:ro" \
		-v "$(pwd)/tests:$APP_DIR/tests:ro" \
		-v "$(pwd)/$LINT_DIR:$APP_DIR/$LINT_DIR:rw" \
		-v "$(pwd)/.pylintrc:$APP_DIR/.pylintrc:ro" \
		--entrypoint $APP_DIR/$LINT_DIR/lint.sh \
		"$dock_tag" \
		$NAME
}

test_code() {
	export dock_tag="$1"
	rm -rf tests/__pycache__ $L_DIR/__pycache__
	docker run --rm \
		-v "$(pwd)/$L_DIR/errors.py:$APP_DIR/$L_DIR/errors.py:ro" \
		-v "$(pwd)/$L_DIR/light_clightning.py:$APP_DIR/$L_DIR/light_clightning.py:ro" \
		-v "$(pwd)/$L_DIR/light_eclair.py:$APP_DIR/$L_DIR/light_eclair.py:ro" \
		-v "$(pwd)/$L_DIR/light_lnd.py:$APP_DIR/$L_DIR/light_lnd.py:ro" \
		-v "$(pwd)/$L_DIR/lighter.py:$APP_DIR/$L_DIR/lighter.py:ro" \
		-v "$(pwd)/$L_DIR/macaroons.py:$APP_DIR/$L_DIR/macaroons.py:ro" \
		-v "$(pwd)/$L_DIR/utils.py:$APP_DIR/$L_DIR/utils.py:ro" \
		-v "$(pwd)/$L_DIR/settings.py:$APP_DIR/$L_DIR/settings.py:ro" \
		-v "$(pwd)/tests:$APP_DIR/tests:ro" \
		-v "$(pwd)/.coveragerc:$APP_DIR/.coveragerc:ro" \
		--entrypoint $ENV_DIR/bin/pytest \
		"$dock_tag" \
		-v --cov=$L_DIR --cov-report=term-missing
}

# Calls the set called function with the set params passed as a single word
if [ -z "$params" ]; then
	$called_function
else
	$called_function $params
fi
