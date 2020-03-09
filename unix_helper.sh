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
PKG_NAME='lighter_bitcoin'

DOCKER_NS='inbitcoin'
DOCKER_REPO=${DOCKER_NS}/${NAME}
DOCKER_DIR='docker'

me=$(basename "$0")

_show_help() {
    echo "Usage: ${me} [target]"
    echo "Targets:"
    echo " - docker_build:   builds Lighter docker image"
    echo " - clean:          cleans Lighter directory from downloaded/generated files"
    echo " - test:           tests Lighter code"
    echo " - lint:           lints Lighter code"
    echo " - version:        gets Lighter version"
    echo " - help:           shows this message"
    echo ""
    echo "Default: help"
    echo "Note: Uncommented targets are not meant to be called manually"
}

params=$*
if [ -z "$params" ]; then
    _show_help
    exit 0
fi

_die() {
    _echoerr "$@"
    exit 2
}

_echoerr() {
    echo "$@" 1>&2;
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

get_host_tag_arch() {
    case $(uname) in
        Linux  ) _get_linux_arch ;;
        Darwin ) _get_darwin_arch ;;
        *      ) _echoerr "Your OS may be unsupported" ;;
    esac
    if [ -z "${host_tag_arch}" ]; then
        _echoerr "Your architecture may be unsupported"
        export host_tag_arch="amd64"
    fi
    echo "${host_tag_arch}"
}

clean() {
    python setup.py clean --all
}

help() {
    _show_help
}

docker_build() {
    version=$(version)
    docker_tag=${DOCKER_REPO}:${version}
    get_host_tag_arch > /dev/null
    dockerfile="${DOCKER_DIR}/Dockerfile"
    echo "Building docker image for ${host_tag_arch}..."
    [ "${DEVELOPMENT}" = 1 ] && opts="--build-arg DEVELOPMENT=1" \
        docker_tag=${DOCKER_REPO}:${version}-dev
    CMD=$(echo docker build -f "${dockerfile}" -t "${docker_tag}" ${opts} .)
    echo "> ${CMD}" && eval "${CMD}"
}

lint() {
    python3 setup.py lint
}

test() {
    python3 setup.py test
}

version() {
    ver=$(python3 -c "from ${PKG_NAME} import __version__; print(__version__)")
    echo "${ver}"
}

# Calls the set called function with the set params passed as a single word
if [ -z "$params" ]; then
	$called_function
else
	$called_function $params
fi
