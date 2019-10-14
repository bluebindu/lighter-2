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

""" Generator of a compose file to run Lighter in docker """

import sys

from os import environ as env, linesep
from re import match
from string import ascii_letters

ALPHABET = ascii_letters

COMPOSE = []

HEADER = [
    'version: "3.2"',
    '',
    'services:',
    '  lighter:',
    '    image: "{}/lighter:{}"'.format(env['DOCKER_NS'], env['VERSION']),
    '    logging:',
    '      options:',
    '        max-size: "77m"',
    '        max-file: "7"',
    '    container_name: lighter',
    '    restart: "unless-stopped"',
]

VOLUMES_COMMON = [
    '    volumes:',
    '      - ./lighter-data/config:{}/lighter-data/config:ro'.format(
        env['APP_DIR']),
    '      - {}:{}/lighter-data/certs/server.key:ro'.format(
        env['SERVER_KEY'], env['APP_DIR']),
    '      - {}:{}/lighter-data/certs/server.crt:ro'.format(
        env['SERVER_CRT'], env['APP_DIR']),
    '      - {}:{}/lighter-data/db'.format(
        env['DB_DIR'], env['APP_DIR']),
    '      - {}:{}/lighter-data/macaroons'.format(
        env['MACAROONS_DIR'], env['APP_DIR']),
]

VOLUMES_IMPLEMENTATIONS = {
    'clightning': {
        'CL_CLI_DIR': '/srv/clightning/cli:ro',
        'CL_RPC_DIR': '/srv/clightning/.lightning:ro'
    },
    'eclair': {
    },
    'lnd': {
        'LND_CERT_DIR': '/srv/lnd/certs:ro',
        'LND_MAC_PATH': '/srv/lnd/tmp/lnd.macaroon:ro'
    }
}

NETWORKS = ['networks:']

VOLUMES = ['volumes:']


def _exit(message):
    """ Exits printing a message """
    print(message)
    sys.exit(1)


def _render_compose(implementation):
    """ Extends the compose list in the right order """
    COMPOSE.extend(HEADER)
    _add_myuid()
    COMPOSE.extend(VOLUMES_COMMON)
    _add_volumes(implementation)
    _add_ports()
    _add_network(env.get('DOCKER_NET'))

    for section in [NETWORKS, VOLUMES]:
        if len(section) > 1:
            COMPOSE.extend([''])
            COMPOSE.extend(section)


def _add_myuid():
    """ Adds MYUID as a docker environemnt variable, if shell var is set """
    myuid = env.get('MYUID')
    if myuid:
        COMPOSE.extend(['    environment:',
                        '        MYUID: {}'.format(myuid)])


def _add_volumes(implementation):
    """
    Add volumes to the compose list, checking if they are docker volumes or
    host directories
    """
    volumes_implementation = VOLUMES_IMPLEMENTATIONS[implementation]
    for key, path in volumes_implementation.items():
        source = env.get(key)
        if source:
            if _is_docker_volume(source):
                _declare_volume(source)
            COMPOSE.extend(['      - {}:{}'.format(source, path)])


def _is_docker_volume(string):
    """ Check if a string matches the regex of a docker volume """
    return True if match('^[a-zA-Z0-9._-]+$', string) else False


def _declare_volume(volume):
    """ Adds a docker volume (as an external volume) to the volumes section """
    vol = [
        '  {}:'.format(volume),
        '    external: true']
    VOLUMES.extend(vol)


def _add_ports():
    """ Exposes allowed ports """
    ports = ['    ports:']
    port = env.get('PORT')
    if _is_port_allowed(port):
        ports.extend(['      - {}:{}'.format(port, port)])
    if len(ports) > 1:
        COMPOSE.extend(ports)


def _is_port_allowed(port):
    """ Checks if port is allowed """
    try:
        return int(port)
    except Exception:
        _exit('Invalid port')


def _add_network(docker_net):
    """ Adds an external docker network """
    if docker_net:
        net = [
            '    networks:',
            '      - {}'.format(docker_net)]
        COMPOSE.extend(net)
        net = [
            '  {}:'.format(docker_net),
            '    external: true']
        NETWORKS.extend(net)


def _write_file(name):
    """
    Writes compose elements, separated by a new line, in a compose.yml file
    """
    with open(name, 'w') as file:
        for line in COMPOSE:
            file.write(line + linesep)


def generate_compose():
    """
    Generates a compose.yml file, for running in docker, starting from
    Lighter's config variables
    """
    try:
        implementation = env['IMPLEMENTATION'].lower()
        _render_compose(implementation)
        _write_file('compose.yml')
    except KeyError as err:
        _exit('{} environment variable needs to be set'.format(err))


if __name__ == '__main__':
    generate_compose()
