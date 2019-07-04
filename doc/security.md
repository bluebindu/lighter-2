# Security

We strive to keep Lighter as secure as possible.
In order to accomplish this, we added an UnlockerServicer and
[macaroons](https://ai.google/research/pubs/pub41892)
as authorization method.

To handle security, `make secure` is available.
This will ask for Lighter's password.
On a first run (or when overriding the database) this will be the new password
that will be used to encrypt the secrets and will be required to unlock Lighter
when starting.
If the database has been kept, the provided password will be used to verify its
correctness and manage implementation secrets.

The database will contain the root key to verify macaroons
and, depending on the configured implementation, the implementation secrets.
All secrets are encrypted using the _secretbox_ symmetric key algorithm and a
32-byte key derived from the password using _scrypt_.

If security features are enabled, the UnlockerServicer will start before the
LightningServicer and ask for a password to unlock Lighter's database.


## Implementation secrets

### c-lightning

Lighter connects directly to c-lightning's RPC-JSON socket so there are no
secrets to store, at the moment.
To secure communication with the node, we suggest using Docker.

### eclair

We crypt eclair's password (`eclair.api.password` to be set on the eclair node,
along with `eclair.api=True`). <sup>1</sup>

If configured to run with eclair, `make secure` will ask to insert or
update its password.

### lnd

We crypt lnd's macaroon, if given. <sup>2</sup>

If configured to run with lnd, `make secure` will insert or update the macaroon
(if a path to the file has been provided) and then ask if it should be used when
connecting to lnd. Connection with no macaroon will be attempted if none is
available (implies `--no-macaroons` set on the lnd node).

Attention, the choice of lnd macaroon could impact some Lighter functionalities,
as some operations could be forbidden.

#### Notes

1. _from version 1.0.0 variable_ `ECL_PASS` _is no longer necessary_
2. _from version 1.0.0 variables_ `LND_MACAROON` _and_ `LND_MACAROON_DIR` _are no longer
   necessary_


## Lighter's macaroons

We use `pymacaroons` and `macaroonbakery` python packages to create and handle
macaroons.
A randomly generated 32-bytes key is used as root key to sign macaroons.
This key is stored encrypted in the database.

At the moment, we provide 3 different macaroons:

|                  | admin | readonly | invoices |
| ---------------- | ----- | -------- | -------- |
| ChannelBalance   |   ☇   |     ☇    |          |
| CheckInvoice     |   ☇   |     ☇    |     ☇    |
| CreateInvoice    |   ☇   |          |     ☇    |
| DecodeInvoice    |   ☇   |     ☇    |     ☇    |
| GetInfo          |   ☇   |     ☇    |     ☇    |
| ListChannels     |   ☇   |     ☇    |     ☇    |
| ListInvoices     |   ☇   |     ☇    |     ☇    |
| ListPayments     |   ☇   |     ☇    |          |
| ListPeers        |   ☇   |     ☇    |     ☇    |
| ListTransactions |   ☇   |     ☇    |          |
| NewAddress       |   ☇   |          |          |
| OpenChannel      |   ☇   |          |          |
| PayInvoice       |   ☇   |          |          |
| PayOnChain       |   ☇   |          |          |
| WalletBalance    |   ☇   |     ☇    |          |
