# Lighter - enabling the 3rd layer with consensus on the 2nd

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


### Implementations :zap:

Currently, it supports the main LN implementations <sup>1</sup>:

- [c-lightning](https://github.com/ElementsProject/lightning)
  (v0.8.2.1 <sup>2</sup>) by Blockstream
- [eclair](https://github.com/ACINQ/eclair) (v0.3.3) by Acinq
- [electrum](https://github.com/spesmilo/electrum) (unreleased <sup>3</sup>)
  by Thomas Voegtlin
- [lnd](https://github.com/lightningnetwork/lnd) (v0.10.1-beta) by Lightning
  Labs

### How it works

Lighter exposes a gRPC client interface, which uses protocol buffers,
Google’s open source mechanismn for serializing structured data.
This enables generation of efficient data access classes in 11 languages from
the proto definition using `protoc`, making it possible for polyglot services
to connect easily.

From the Lighter user's point of view, implementation-specific configuration
variables and software dependencies are the only differences between the
various supported implementations.

To secure Lighter we use macaroons as authorization mechanism.
See [Security](/doc/security.md) to get more information on how Lighter is
secured.


#### Notes
1. _at the moment Lighter supports only the specified versions of the LN nodes
  (not provided within this software)_
2. _`c-lightning`'s `fundchannel` and `pay` plugins are required_
3. _`electrum` might be unstable, you should not use it on mainnet_


## Requirements

First of all, Lighter will need to connect to an already existing and
supported LN node, which determines the main configuration parameter,
`implementation`.

Before it's run, Lighter needs to be configured according to the chosen
implementation.

In order to run Lighter some software dependencies have to be met.
Some requirements are determined by the configured implementation.

Lighter will check at runtime for the availability of the required
dependencies, based on its configuration.


### System dependencies

- Linux <sup>1</sup> or macOS <sup>2</sup>
(_Windows may work, but is not supported_)
- Python 3.5+ <sup>3</sup>
- [optional] libscrypt 1.8+ (_faster start_)

### Resources

Resource demand should be pretty low.
More precise recommendations will be available in the future
as gathered real-world usage data grows.

- CPU: 1 core is enough
- RAM: ~64MB when idling
- disk: docker image weights ~170MB

#### Notes

1. _tested on Debian 10 Buster_
2. _tested on macOS 10.13 High Sierra_
3. _tested with python3.7_


## Building

#### Building locally

In order to install Lighter, run
```bash
$ pip install .
```
Usage of `virtualenv` is recommended.

#### Building docker image

To build a docker image, run:
```bash
$ ./unix_helper.sh docker_build
```

#### Notes

1. _supported architectures: amd64, arm32v7 (may require additional
    dependencies)_


## Configuring

Lighter needs to be configured before the execution of any other operation
(`build` excluded).
See [Configuring](/doc/configuring.md) for instructions on how to configure
Lighter.


## Securing

In order to run Lighter, you need to configure the necessary secrets and set a
password to manage and protect them.
To do so, run:
```bash
$ lighter-secure
```

This can be run interactively or not.
It will create or update Lighter's database and macaroon files in their
configured path.
All secrets will be stored in encrypted form (in the database) and
made available to Lighter only at runtime, after it has been unlocked.

Read [Security](/doc/security.md) for more details.


## Running

To start Lighter's gRPC server, run:

```bash
$ lighter
```


## Using

Lighter can be operated through its gRPC client interface.
A CLI with bash and zsh completion support is also available for maintenance
and testing.

The `lighter.proto` defines the structure for the data to be serialized
and can be found [here](/lighter/lighter.proto).
gRPC client libraries for supported languages can be generated from this file.
[Generation instructions](/doc/client_libraries.md) are available.

Protocol buffer data is structured as messages (and enums), where each message
can contain a series of name-value pairs called fields.
Several services can be defined in the proto file, each one
including different methods.
Our proto file contains two services: _Unlocker_ and _Lightning_.
The former unlocks Lighter.
The latter only starts after it is unlocked and provides all the supported LN
node operations <sup>1</sup>.

A set of **documentation for the gRPC APIs**, along with example code in
Python, Go, Node.js and Bash can be found at our
[lighter-doc API page](https://lighter-doc.inbitcoin.it).

To unlock Lighter and have a full list of available commands of
Lighter's **CLI**, run:
```bash
$ cliter unlocklighter
$ cliter --help
```
To activate completion support, first locate completion scripts,
which are in `share/doc/lighter_bitcoin/examples/`, relative to python
installation path.
Possible installation paths: `/venv/path/`, `~/.local/`, `/usr/local/`.

Then, you can add completion support by adding the appropriate line to your
shell's RC file:
- `~/.bashrc`: `. /path/to/complete-cliter-bash.sh`
- `~/.zshrc`: `. /path/to/complete-cliter-zsh.sh`

To **pair** Lighter with a client, run:
```bash
$ lighter-pairing
```
This will create two URIs to allow easy retrieval of
connection data (`lighterconnect://<host>:<port>[?cert=<PEM certificate>]`)
and macaroon (`macaroon:<chosen macaroon>`).
As output format, it will let you choose between QR codes and text.

### Clients with pairing support

- [Globular](https://gitlab.com/inbitcoin/globular), Android wallet

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


## Contributing

All contributions to Lighter are welcome.<br>
We will strive to keep Lighter updated but help is appreciated,
especially with keeping support for underlying implementations updated,
since they are still in the early stages and therefore significant changes
may occur.

To learn more on how and where to contribute, continue reading
[here](/CONTRIBUTING.md).
