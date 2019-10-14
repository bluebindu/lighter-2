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
On successive runs, if the database has not be overridden (first
`make secure` question), the provided password will be used to verify its
correctness, manage implementation secrets and generate macaroons rootkey.

The database will contain a token to verify password correctness and, depending
on the current configuration, the root key to verify macaroons and
implementation secrets.
Each secret is encrypted using the _secretbox_ symmetric key algorithm and
a different 32-byte key derived from a unique password using _scrypt_.

The UnlockerServicer will start before the LightningServicer and ask for a
password that will be checked and then used to decrypt the secrets stored in
Lighter's database.

## Password Strength

We strongly suggest the usage of a
[password manager](https://en.wikipedia.org/wiki/List_of_password_managers)
to create and store on users' behalf a randomly crafted strong password.
Lighter can generate it for you when running `make secure` for the first
time or after choosing to delete the database.
The auto generated password is by default 12 chars long and uses a 64-char
alphabet.
Alternatively one can have a look at the following
[guidelines](https://en.wikipedia.org/wiki/Password_strength#Guidelines_for_strong_passwords)
for good practices.

### Scrypt guarantees

The use of _scrypt_ to stretch the password with a random salt helps it to
become stronger against brute-force and rainbow-table attacks. The
[_scrypt_ whitepaper](http://www.tarsnap.com/scrypt/scrypt.pdf)
gives estimation on the cost of the hardware needed to crack a password in one
year on average with the default `cost_factor` at 2<sup>14</sup>, as compared
to other key derivation functions:

|KDF   |6 letters|8 letters|8 chars|10 chars|
|:-----|--------:|--------:|------:|-------:|
|PBKDF2|<$1      |<$1      |$18k   |$160M   |
|bcrypt|<$1      |$4       |$130k  |$1.2B   |
|scrypt|<$1      |$150     |$4.8M  |$43B    |

Although these values might become off by a factor 10 due to hardware cost
instability or performance improvement, they offer a good idea on the confidence
one can put into a password.
__Important note:__ these values only apply in the case of _randomly_ chosen
passwords; the ones created to be remembered by humans tend to be weak against
pure dictionary attacks.

### Entropy source

The confidence that can be put on the solutions described above depends
significantly from the available entropy source. For this reason we use a
blocking (`/dev/random`) source of randomness which only returns when the
Operating System has enough entropy to fulfill the request.
On most devices this should not affect execution time, but if it is the case
you can help this process by doing one or more of the following when you will
be asked to:
* randomly utilize an input device (keyboard, mouse) connected to the host
running Lighter
* install entropy collecting tools like
[haveged](https://linux.die.net/man/8/haveged)
* install a hardware TRNG
* type `unsafe` and press enter to use a non-blocking entropy source; this
choice will NOT be remembered for later

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

We crypt lnd's macaroon <sup>2</sup> and password, if given.

If configured to run with lnd, `make secure` will insert or update the macaroon
(if a path to the file has been provided) and then ask if it should be used when
connecting to lnd. Connection with no macaroon will be attempted if none is
available (implies `--no-macaroons` set on the lnd node).
Finally it will ask to insert, skip or update lnd's password
(updating and then skipping will remove any precedently saved password).

Attention, the choice of lnd macaroon could impact some Lighter functionalities,
as some operations could be forbidden.

The `UnlockNode` API and the `UnlockLighter`'s boolean option `unlock_node`
will be enabled after providing lnd's password.

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
| CloseChannel     |   ☇   |          |          |
| CreateInvoice    |   ☇   |          |     ☇    |
| DecodeInvoice    |   ☇   |     ☇    |     ☇    |
| GetInfo          |   ☇   |     ☇    |     ☇    |
| ListChannels     |   ☇   |     ☇    |     ☇    |
| ListInvoices     |   ☇   |     ☇    |     ☇    |
| ListPayments     |   ☇   |     ☇    |          |
| ListPeers        |   ☇   |     ☇    |     ☇    |
| ListTransactions |   ☇   |     ☇    |          |
| LockLighter      |   ☇   |          |          |
| NewAddress       |   ☇   |          |          |
| OpenChannel      |   ☇   |          |          |
| PayInvoice       |   ☇   |          |          |
| PayOnChain       |   ☇   |          |          |
| UnlockNode       |   ☇   |          |          |
| WalletBalance    |   ☇   |     ☇    |          |
