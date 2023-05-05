# Credentials in Briolette

There are a number of credentials present throughout briolette, each with its
own capabilities.


## Service certificates

All operator services are expected to operate on top of a normal TLS deployment
where the client can rely on server authenticity based on the certificates and keys
held by the server.

None of briolette's trust depends on TLS functioning, it does provide heightened
assurance against denial of service or service disruption attacks.

## State signing key

The state signing key is the most critical cryptographic key in the system.
After a system-defined period of time has elapsed, a 'epoch', briolette
system-wide state is updated.  This update includes the current epoch number (a
monotonically increasing 64-bit integer, usually based on wall-clock time), any
ticket group numbers that have been temporarily blocked from the system
(revoked), and the other public keys for the remainder of the system that a
client, or wallet, device must know: token transfer public key, ticket server
public key, issuing mint public keys, etc.

The level of trust given to the state signing key enables a compromise between
in-the-field key rotation with minimal gossip overhead. A secondary signature
over the extended state (epoch) data may be appropriate to introduce if the
risk introduced is too high.

### Installation

The initial state signing key is installed on the wallet device by the wallet
vendor or through an out-of-band installation process.  Knowledge of the state
server (clerk) and the state signing key is all that is required for a
certified wallet to participate in different briolette systems.

See discussion of the 'Network Access Credential' for more.

### Usage

The state signing key does not need to be online and may be air gapped. The
data it signs is fixed and well-formed, so the process for using the signing
key, or keys, may be accompanied by additional software validation both on and
off the signing infrastructure.  The signer operates over the next epoch, a
bitfield of revoked groups, and the extended epoch data cryptographic hash.
The extended epoch data contains the all other signing keys, as well as the
alternative state signing keys.

Epoch updates are not expected in real-time and as such, the generation of
the new epoch data and signing process may be subject to high levels of
assurance.

## Network Access Credential (NAC) Issuer Key

Wallet vendors will have at least one NAC issuer key. This key is used to grant
network access credentials to wallets. The associated group public key must be
known and accepted by briolette system operators for the credential to be used.

The issuer may require the wallet to have a proprietary key or perform some
other service to be accepted for credential issuance.

## Network Access Credential (NAC)

The NAC is used by a wallet to connect to briolette operator services and is
required for acquiring a token transfer credential.

Signatures over requests with epoch-bound basenames may be used to create
linkable signatures over time periods.  This will allow operator services to
limit requests from any given wallet during a time period without being able
to uniquely identify that wallet in the future.

## Token Transfer Credential (TTC) Issuer Key

This key is usually held by the system operator and is used to grant token
transfer credentials to wallets.  Wallets will need to request a TTC upon
setup for a given operator and its request must be authenticated by the
wallet's NAC with a known NAC group public key.

## Token Transfer Credential (TTC)

The TTC is used by the wallet to send and receive tokens.  The wallet holds the
private key and the credential acts as a "public" key.  The credential itself
is never used directly.  Instead it may be randomized prior to use.

Prior to transacting, a wallet must pre-randomize its credential several times.
It will take these randomized credentials and present them to the ticket clerk
service (signed with the wallet's NAC).  The ticket clerk will return signed
tickets which may be used as the destination to receive tokens at.

When transferring received tokens, the wallet must use the same randomized
credential from the signed ticket the token was transferred to when signing the
transaction.

## Token Signing Key

The token signing key is the minting key.  It fixates the token descriptor data
with its signature and assigns the first recipient of a token.

## Transfer Ticket Signing Key

This key is held by the ticket clerk service and is used to sign transfer tickets
which are built from randomized TTCs and specific policy attributes, such as
expiration times.


