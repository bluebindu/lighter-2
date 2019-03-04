# Lighter - The Lightning Network Wrapper

Lighter is a Lightning Network node wrapper.

It provides a uniform interface to the main LN implementations,
allowing client code to be agnostic on which node is running under the hood
and therefore focus on functionality.

This means that the underlying LN node implementation can be
changed anytime, affecting client code as little as possible.
Each underlying implementation can, and indeed does, implement some features
with "little" differences. Lighter strives to keep a uniform interface
at all times, drawing a common line where implementations differ
and always choosing to stay BOLT-compliant as much as possible.

Lighter was initially born to handle this complexity.

The purpose of the project is to allow developers of LN-based front-end
applications to code in peace without having to loyalize to a single
implementation.
As a bonus, this helps to keep the competitiveness among LN implementers high.

Lighter - Where all the weight of the world is just a little bit lighter,
on our shoulders.

This is an open project under the GNU AGPLv3 license.


#### Implementations :zap:

Currently, it supports the main LN implementations:

- [c-lightning](https://github.com/ElementsProject/lightning) (v0.7.0) by
  Blockstream
- [eclair](https://github.com/ACINQ/eclair) (v0.2-beta9) by Acinq
- [lnd](https://github.com/lightningnetwork/lnd) (v0.5.2-beta) by Lightning Labs


#### How it works

Lighter exposes a gRPC client interface, which uses protocol buffers,
Google’s open source mechanismn for serializing structured data.
This enables generation of efficient data access classes in 11 languages from
the proto definition using `protoc`, making it possible for polyglot services
to connect easily.

From the Lighter user's point of view, implementation-specific configuration
variables and software dependencies are the only differences between the
various supported implementations.

Stay tuned for future improvements. Better security is coming (hint: macaroons).


# Requirements

First of all, Lighter will need to connect to an already existing and
supported LN node, which determines the main configuration parameter,
`IMPLEMENTATION`.

Before it's run, Lighter needs to be configured according to the chosen
implementation.

In order to run Lighter some software dependencies have to be met.
Some requirements are determined by choosing to either run Lighter locally
or in docker, others by the configured implementation.

Lighter will check at runtime for the availability of the required
dependencies, based on its configuration.


### System dependencies

- **common**
    - virtualenv
    - make
    - bash
    - rm
    - which

- **locally**
    - Linux <sup>1</sup>
      or macOS <sup>2</sup>
      (_Windows may work, but is not supported_)
    - Python 3.5

- **in docker**
    - Linux <sup>1</sup>,
      macOS <sup>2</sup>
      or Windows <sup>3</sup>
    - Python 3 <sup>4</sup>
    - docker

### Implementation dependencies

- **eclair**
    - chmod
    - curl
    - jq

- **lnd**
    - curl
    - unzip

### Resources

Resource demand should be pretty low.
More precise recommendations will be available in the future
as gathered real-world usage data grows.

- CPU: 1 core is enough
- RAM: ~32MB when idling
- disk: docker image weights ~300MB

#### Notes

1. _tested on Debian 9 Stretch_
2. _tested on macOS 10.13 High Sierra_
3. _not tested_
4. _tested with python3.5_


# Building

All build operations are automated in a [Makefile](/Makefile).
Run `make help` to see available targets.

#### Building locally

In order to install Lighter with support for all implementations,
run
```bash
$ make all
```

otherwise, to support a single implementation, run
```bash
$ make $IMPLEMENTATION
```

See [Implementations](#implementations-) above for possible `$IMPLEMENTATION`
values.

#### Building in docker

To create the Dockerfile for your architecture
<sup>1</sup>
and build a docker image, run:
```bash
$ make docker
```

#### Notes

1. _supported architectures: amd64, arm32v7_


# Configuring

All configuration options can be set in the `lighter-data/config` file.
See [config.sample](/lighter-data/config.sample) for a commented example.
If run without a config file, the example file will be copied in place and
left behind for the user to edit.

Paths are relative to the project directory, unless otherwise stated.

### Lighter settings

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `IMPLEMENTATION` <sup>1</sup> | Implementation to use (possible values: `clightning`, `eclair`, `lnd`; no default) |
| `ALLOW_INSECURE_CONNECTION`   | Set to `1` to make Lighter listen to port 17080 in cleartext (default `0`) |
| `ALLOW_SECURE_CONNECTION`     | Set to `1` to make Lighter listen to port 17443 with TLSv1.2 (default `0`) |
| `SERVER_KEY` <sup>2</sup>     | Private key path (default `./lighter-data/certs/server.key`)               |
| `SERVER_CRT` <sup>2</sup>     | Certificate (chain) path (default `./lighter-data/certs/server.crt`)       |
| `LOGS_DIR`                    | Location <sup>3</sup> to hold log files (default `./lighter-data/logs`)    |
| `DOCKER`                      | Set to `1` to run Lighter in docker when calling `make run`, set to 0 to run locally (default `1`) |
| `DOCKER_NS`                   | Namespace for docker image (default `inbitcoin`)                           |
| `DOCKER_NET`                  | External docker network Lighter's container should be connected to         |

### Implementation settings

| Variable                     | Description                                                     |
| ---------------------------- | --------------------------------------------------------------- |
| `CL_CLI_DIR`                 | c-lightning location <sup>3</sup> containing `CL_CLI`           |
| `CL_CLI`                     | c-lightning  cli binary (relative; default `lightning-cli`)     |
| `CL_RPC_DIR` <sup>4</sup>    | c-lightning location <sup>3</sup> containing `CL_RPC`           |
| `CL_RPC` <sup>5</sup>        | c-lightning JSON-RPC socket (relative; default `lightning-rpc`) |
| `ECL_HOST`                   | eclair host <sup>6</sup> (default `localhost`)                  |
| `ECL_PORT` <sup>7</sup>      | eclair port (default `8080`)                                    |
| `ECL_PASS` <sup>8</sup>      | eclair password, which will be filled in eclair-cli at runtime  |
| `LND_HOST`                   | lnd host <sup>6</sup> (default `localhost`)                     |
| `LND_PORT`                   | lnd port (default `10009`)                                      |
| `LND_CERT_DIR`               | lnd location <sup>3</sup> containing `LND_CERT`                 |
| `LND_CERT`                   | lnd TLS certificate (default `tls.cert`)                        |
| `LND_MACAROON_DIR` <sup>9</sup> | lnd location <sup>3</sup> containing `LND_MACAROON`          |
| `LND_MACAROON` <sup>10</sup> | lnd macaroon file (default `admin.macaroon`)                    |


#### Notes

1. _implementation value is case-insensitive_
2. _example self-signed TLS certificate generation one-liner:_
   `openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=lighter.example.com"`
3. _location can be a local directory or the name of an existing docker volume;
   path can be absolute or relative, if relative it has to start with_ `./`
4. _option:_ `lightning-dir` _(usually ~/.lightning)_
5. _option:_ `rpc-file` _(expected to be owned by uid 1000; usually
   ~/.lightning/lightning-rpc)_
6. _host can be IP, FQDN or docker container reference (id, name,
   compose service)_
7. _option:_ `eclair.api.port` _(usually 8080)_
8. _option:_ `eclair.api.password` _(to be set on eclair, along with
   eclair.api to True)_
9. _implies_ `--no-macaroons` _if unset, enables macaroon support otherwise_
10. _attention, could impact some Lighter functionalities_


# Running

The following command runs Lighter's gRPC server
according to the configured scenario.

```bash
$ make run
```

#### Additional docker-only commands

Follow logs:
```bash
$ make logs
```

Stop the running container:
```bash
$ make stop
```


# Using

Lighter can be operated through its gRPC client interface.

The `lighter.proto` defines the structure for the data to be serialized
and can be found [here](/lighter/lighter.proto).
gRPC client libraries for supported languages can be generated from this file.
[Generation instructions](/doc/client_libraries.md) are available.

Protocol buffer data is structured as messages (and enums), where each message
can contain a series of name-value pairs called fields.
Several services can be defined in the proto file, each one
including different methods.
Our proto file contains one service, _Lightning_, which includes the methods for
all the supported operations <sup>1</sup>.

A set of documentation for the gRPC APIs, along with example code in Python
and Go, can be found at our
[lighter-doc api page](https://lighter-doc.inbitcoin.it).


#### Notes

1. _some operations may not be supported for some implementations, see
    [Supported APIs](/doc/supported_apis.md) for details_
2. _please note there are
   [options](https://developers.google.com/protocol-buffers/docs/proto3#options)
   that can be added to the proto file_
3. _for more information, check the
   [proto3](https://developers.google.com/protocol-buffers/docs/proto3)
   language guide and the developer documentation for
   [gRPC](https://grpc.io/docs/)_


# Contributing

All contributions to Lighter are welcome.<br>
We will strive to keep Lighter updated but help is appreciated,
especially with keeping support for underlying implementations updated,
since they are still in the early stages and therefore significant changes
may occur.

To learn more on how and where to contribute, continue reading
[here](/CONTRIBUTING.md).
