#!/usr/bin/make -f
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

NAME        = lighter
VERSION    ?= 1.0.0

DOCKER_NS  ?= inbitcoin
DOCKER_REPO = $(DOCKER_NS)/$(NAME)
DOCKER_TAG  = $(DOCKER_REPO):$(VERSION)

COM_DEPS    = id rm tr virtualenv
ECL_DEPS    = curl jq
LND_DEPS    = curl unzip

COM_PIPS    = grpcio==1.19.0 grpcio-tools==1.19.0 pymacaroons==0.13.0 macaroonbakery==1.2.1 pylibscrypt==1.7.1 pynacl==1.3.0 click==7.0 protobuf==3.7.1
DEV_PIPS    = pytest-cov pylint pycodestyle
LND_PIPS    = googleapis-common-protos==1.5.8

SCRIPT      = ./unix_make.sh

TAGS_ARCH   = amd64 arm32v7

CONFIG_FILE = lighter-data/config

ifeq ($(shell test -r $(CONFIG_FILE) && echo -n yes), yes)
	include $(CONFIG_FILE)
endif


# User targets

default: help

all: check setup build

clightning: common

eclair: common check_eclair setup_eclair

lnd: common check_lnd setup_lnd build_lnd

docker:
	@ $(SCRIPT) docker_build $(DOCKER_REPO) $(VERSION) $(TAGS_ARCH)

secure:
	@ $(SCRIPT) secure $(CONFIG_FILE) $(VERSION)

run:
	@ $(SCRIPT) run $(CONFIG_FILE) $(VERSION)

cli:
	@ $(SCRIPT) cli $(CONFIG_FILE) $(VERSION)

logs:
	@ $(SCRIPT) logs

stop:
	@ $(SCRIPT) stop

clean:
	@ $(SCRIPT) clean

version:
	@ echo $(VERSION)

help:
	@ echo "Usage: make [target]\n"
	@ echo "Targets:"
	@ echo " - all:          gets Lighter ready for all implementations"
	@ echo " - clightning:   gets Lighter ready for clightning"
	@ echo " - eclair:       gets Lighter ready for eclair"
	@ echo " - lnd:          gets Lighter ready for lnd"
	@ echo " - docker:       builds Lighter docker image"
	@ echo " - secure:       handles Lighter and implementation secrets"
	@ echo " - run:          runs Lighter (in docker or locally)"
	@ echo " - cli:          runs an environment to call cliter (in docker or locally)"
	@ echo " - logs:         shows Lighter logs (in docker)"
	@ echo " - stop:         stops Lighter (in docker), removing all anonymous volumes attached to it"
	@ echo " - clean:        removes Lighter virtualenv"
	@ echo " - test:         tests Lighter code"
	@ echo " - lint:         lints Lighter code"
	@ echo " - version:      gets Lighter version"
	@ echo " - help:         shows this message"
	@ echo "\nDefault: help"
	@ echo "\nNote: Uncommented targets are not meant to be called manually"


# Development targets

lint: docker
	@ $(SCRIPT) lint_code $(DOCKER_TAG)

test: docker
	@ $(SCRIPT) test_code $(DOCKER_TAG)


# Support targets (should not be called directly)

common: check_common setup_common build_common

check: check_common check_eclair check_lnd

check_common:
	@ $(SCRIPT) check_deps $(COM_DEPS)

check_eclair:
	@ $(SCRIPT) check_deps $(ECL_DEPS)

check_lnd:
	@ $(SCRIPT) check_deps $(LND_DEPS)

setup: setup_common setup_eclair setup_lnd

setup_common:
	@ $(SCRIPT) setup_common $(COM_PIPS)
	@ $(SCRIPT) setup_common $(DEV_PIPS)

setup_eclair:
	@ $(SCRIPT) setup_eclair

setup_lnd:
	@ $(SCRIPT) setup_lnd $(LND_PIPS)

build: build_common build_lnd

build_common:
	@ $(SCRIPT) build_common

build_lnd:
	@ $(SCRIPT) build_lnd


.PHONY: all clightning eclair lnd docker secure run cli logs stop clean test lint help
