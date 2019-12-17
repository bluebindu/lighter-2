# Configuring

All configuration options can be set in the `config` file.
See [config.sample](/examples/config.sample) for a commented example.
If run without a config file, the example file will be copied in place and
left behind for the user to edit.

The configuration file along with other data will be stored in a single
directory, `~/.lighter` by default (use `--lighterdir` option to override).
Paths specified in the configuration file are relative to this directory.

### lighter section

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `implementation` <sup>1</sup> | Implementation to use (possible values: `clightning`, `eclair`, `electrum`, `lnd`; no default) |
| `insecure_connection`         | Set to `1` to make Lighter listen in cleartext (default `0`). Implies disabling macaroons. |
| `port`                        | Lighter's listening port (default `1708`)                                  |
| `server_key` <sup>2</sup>     | Private key path (default `./certs/server.key`)                            |
| `server_crt` <sup>2</sup>     | Certificate (chain) path (default `./certs/server.crt`)                    |
| `logs_dir`                    | Location <sup>4</sup> to hold log files (default `./logs`)                 |
| `logs_level`                  | Desired console log level (possible values: `critical`, `error`, `warning`, `info`, `debug`; default `info`) |
| `db_dir`                      | Location to hold the database (default `./db`)                             |
| `macaroons_dir`               | Location to hold macaroons (default `./macaroons`)                         |
| `disable_macaroons` <sup>3</sup> | Set to `1` to disable macaroons authentication (default `0`)            |

### cliter section

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `rpcserver`                   | Lighter host[:port] (default `localhost:1708`)                             |
| `tlscert`                     | Lighter certificate (chain) path (default `./certs/server.crt`)          |
| `macaroon`                    | Lighter macaroon path (default `./macaroons/admin.macaroon`)             |
| `insecure`                    | Set to `1` to connect to Lighter in cleartext  (default `0`)               |
| `no_macaroon`                 | Set to `1` to connect to Lighter with no macaroon (default `0`)            |


### clightning section

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `cl_cli_dir`                  | Location <sup>4</sup> containing `cl_cli`                                  |
| `cl_cli`                      | CLI binary name (default `lightning-cli`)                                  |
| `cl_rpc_dir` <sup>5</sup>     | Location <sup>4</sup> containing `cl_rpc`                                  |
| `cl_rpc` <sup>6</sup>         | JSON-RPC socket name (default `lightning-rpc`)                             |

### eclair section

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `ecl_host`                    | Host <sup>7</sup> (default `localhost`)                                    |
| `ecl_port` <sup>8</sup>       | Port (default `8080`)                                                      |

### electrum section

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `ele_host`                    | Host <sup>7</sup> (default `localhost`)                                    |
| `ele_port`                    | Port (default `7777`)                                                      |
| `ele_user`                    | User (default `user`)                                                      |

### lnd section

| Variable                      | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `lnd_host`                    | Host <sup>7</sup> (default `localhost`)                                    |
| `lnd_port`                    | Port (default `10009`)                                                     |
| `lnd_cert_dir`                | Location <sup>4</sup> containing `lnd_cert`                                |
| `lnd_cert`                    | TLS certificate name (default `tls.cert`)                                  |

#### Notes

1. _implementation value is case-insensitive_
2. _example self-signed TLS certificate generation one-liner:_
   `openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=node.example.com" -extensions SAN -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:node.example.com,DNS:lighter,DNS:localhost,IP:127.0.0.1,IP:::1"))`
3. _running Lighter on mainnet with macaroons disabled has severe security
   implications and is highly discouraged, don't do this unless you know
   what you're doing_
4. _location must be a directory;
path can be absolute or relative (to Lighter's data directory)_
5. _option:_ `lightning-dir` _(usually ~/.lightning)_
6. _option:_ `rpc-file` _the JSON-RPC socket needs to be owned by the same user
   Lighter is running as_
7. _host can be an IP or a FQDN_
8. _option:_ `eclair.api.port` _(usually 8080)_
