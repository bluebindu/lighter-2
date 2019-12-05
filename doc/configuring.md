# Configuring

All configuration options can be set in the `lighter-data/config` file.
See [config.sample](/lighter-data/config.sample) for a commented example.
If run without a config file, the example file will be copied in place and
left behind for the user to edit.

Paths are relative to the project directory, unless otherwise stated.

### Lighter settings

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `IMPLEMENTATION` <sup>1</sup> | Implementation to use (possible values: `clightning`, `eclair`, `electrum`, `lnd`; no default) |
| `INSECURE_CONNECTION`         | Set to `1` to make Lighter listen in cleartext (default `0`). Implies disabling macaroons. |
| `PORT`                        | Lighter's listening port (default `1708`)                                  |
| `SERVER_KEY` <sup>2</sup>     | Private key path (default `./lighter-data/certs/server.key`)               |
| `SERVER_CRT` <sup>2</sup>     | Certificate (chain) path (default `./lighter-data/certs/server.crt`)       |
| `LOGS_DIR`                    | Location <sup>4</sup> to hold log files (default `./lighter-data/logs`)    |
| `LOGS_LEVEL`                  | Desired console log level (possible values: `critical`, `error`, `warning`, `info`, `debug`; default `info`) |
| `DB_DIR`                      | Location to hold the database (default `./lighter-data/db`)                |
| `MACAROONS_DIR`               | Location to hold macaroons (default `./lighter-data/macaroons`)            |
| `DISABLE_MACAROONS` <sup>3</sup> | Set to `1` to disable macaroons authentication (default `0`)            |
| `DOCKER_NS`                   | Namespace for docker image (default `inbitcoin`)                           |

### Implementation settings

| Variable                     | Description                                                     |
| ---------------------------- | --------------------------------------------------------------- |
| `CL_CLI_DIR`                 | c-lightning location <sup>4</sup> containing `CL_CLI`           |
| `CL_CLI`                     | c-lightning  cli binary (relative; default `lightning-cli`)     |
| `CL_RPC_DIR` <sup>5</sup>    | c-lightning location <sup>4</sup> containing `CL_RPC`           |
| `CL_RPC` <sup>6</sup>        | c-lightning JSON-RPC socket (relative; default `lightning-rpc`) |
| `ECL_HOST`                   | eclair host <sup>7</sup> (default `localhost`)                  |
| `ECL_PORT` <sup>8</sup>      | eclair port (default `8080`)                                    |
| `ELE_HOST`                   | electrum host <sup>7</sup> (default `localhost`)                |
| `ELE_PORT`                   | electrum port (default `7777`)                                  |
| `ELE_USER`                   | electrum user (default `user`)                                  |
| `LND_HOST`                   | lnd host <sup>7</sup> (default `localhost`)                     |
| `LND_PORT`                   | lnd port (default `10009`)                                      |
| `LND_CERT_DIR`               | lnd location <sup>4</sup> containing `LND_CERT`                 |
| `LND_CERT`                   | lnd TLS certificate (default `tls.cert`)                        |


#### Notes

1. _implementation value is case-insensitive_
2. _example self-signed TLS certificate generation one-liner:_
   `openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=node.example.com" -extensions SAN -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:node.example.com,DNS:lighter,DNS:localhost,IP:127.0.0.1,IP:::1"))`
3. _running Lighter on mainnet with macaroons disabled has severe security
   implications and is highly discouraged, don't do this unless you know
   what you're doing_
4. _location must be a directory;
   path can be absolute or relative, if relative it has to start with_ `./`
5. _option:_ `lightning-dir` _(usually ~/.lightning)_
6. _option:_ `rpc-file` _the JSON-RPC socket needs to be owned by the same user
   Lighter is running as_
7. _host can be an IP or a FQDN_
8. _option:_ `eclair.api.port` _(usually 8080)_
