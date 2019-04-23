# Security

We strive to keep Lighter as secure as possible.
In order to accomplish this, we added an UnlockerServicer and
[macaroons](https://ai.google/research/pubs/pub41892)
as authentication method.

After an initialization phase (`make init`), the DB will contain the key to
unlock macaroons, in encrypted form, and, depending on the configured
implementation (`IMPLEMENTATION` in config file), the implementation secrets.

The UnlockerServicer will start before the LightningServicer and will
ask for a password to unlock Lighter's database (sqlite3).

Secrets are encrypted using a symmetric key algorithm (secretbox) and a
32 bytes key derived from a password using scrypt.


## Implementation secrets

### c-lightning

Nothing yet.

### eclair

We crypt eclair's password (`eclair.api.password` to be set on eclair, along
with eclair.api to True). <sup>1</sup>


### lnd

We crypt lnd's macaroon, if given <sup>2</sup>. <sup>3</sup>

Attention, the choice of macaroon could impact some Lighter functionalities,
as some operations could be forbidden.


## Lighter's macaroons

We use `pymacaroons` and `macaroonbakery` python packages to create and handle
macaroons.
A 32 byte key is used as root key to sign macaroons.
This key is encrypted and written to the database.

At the moment, we provide 3 different macaroons:

|                  | admin.macaroon | readonly.macaroon | invoices.macaroon |
| ---------------- | -------------- | ----------------- | ----------------- |
| ChannelBalance   |       ☇       |    ☇    |     |
| CheckInvoice     |       ☇       |    ☇    |  ☇  |
| CreateInvoice    |       ☇       |         |  ☇  |
| DecodeInvoice    |       ☇       |    ☇    |     |
| GetInfo          |       ☇       |    ☇    |     |
| ListChannels     |       ☇       |    ☇    |     |
| ListInvoices     |       ☇       |    ☇    |     |
| ListPayments     |       ☇       |    ☇    |     |
| ListPeers        |       ☇       |    ☇    |     |
| ListTransactions |       ☇       |    ☇    |     |
| NewAddress       |       ☇       |         |     |
| OpenChannel      |       ☇       |         |     |
| PayInvoice       |       ☇       |         |     |
| PayOnChain       |       ☇       |         |     |
| WalletBalance    |       ☇       |    ☇    |     |


#### Notes

1. _variable_ `ECL_PASS` _is no longer necessary_
2. _giving no macaroon at initialization time implies_ `--no-macaroons` _when
   connecting to lnd at runtime_
3. _variables_ `LND_MACAROON` _and_ `LND_MACAROON_DIR` _are no longer
   necessary_
