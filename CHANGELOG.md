# Changelog
All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.2 - 2019-03-06

### Fixed

- proto: fixed OpenChannel rpc definition
- lnd: fixed missing `max_precision` in `funding_bits` conversion of OpenChannel
- `KeyboardInterrupt` was not triggering `_slow_exit`

## 0.2.1 - 2019-03-04

### Changed

- Updated supported implementation versions

### Fixed

- Utils module tests (oops)
- c-lightning: wrong parameter for timestamp


## 0.2.0 - 2019-02-12

### Added

- New APIs (see support table):
  * ListInvoices
  * ListPayments
  * ListTransactions
  * OpenChannel
  * PayOnChain
- Supported APIs table
- gRPC version update (1.18.0)
- Node.js proto compilation example
- New error mappings
- lnd connection handling decorator
- Checks for required parameters

### Fixed

- Makefile: targets lint and test work on first run
- Dockerfile generation on arm
- c-lightning invoice creation (`check_value` usage)
- lighter.proto reordering (alphabetical sort)


## 0.1.0 - 2018-12-04

### Added

- Protobuf definitions
- Lighter dispatcher
- Support for c-lightning node
- Support for eclair node
- Support for lnd node
- Unified error handling
- Runtime settings management
- Utils common module
- Configuration support
- Graceful exit and signal handling
- Logging
- Test suite
- Building, running, testing and linting orchestration via Makefile
- Docker support with autogeneration of Dockerfile and compose file
- arm32v7 support
- Documentation
