# Layout

Each subdirectory contains a prototype implementation of the named service:

    * mint/
    * registar/
    * clerk/
    * trim/
    * validate/
    * tokenmap/
    * swapper/

With a common crypto interface under crypto/ and a sample wallet under wallet/ and
a default funds receiving service under receiver/.

proto/ contains all the protocol buffers across all services.

simulation/ contains a simplistic agent-based simulator for briolette.

## Mint

The mint creates tokens upon request with a given amount.
- The tokens are minted and transfered to the callers address using their
  clerk-issued ticket.
- The tokens and initial history are added to the tokenmap.

## Registrar

Provides eligible wallets with a proof of knowledge that the
are allowed to participate in the system and assigns a group number
based on the non-uniquely identifying hardware attestation exchange that
occurs.

## Clerk

The clerk provides tickets and system-wide updates. Clerks do not need to be
synchronized, but if limited ticket issuance is desired, synchronization and/or
credential issuer sharding will be necessary for proactive enforcement.

Tickets are not issued to revoked wallets and a limited number of tickets are
issued to quaratined wallets. (Tickets are per-transaction use and have a
system-epoch expiration - the policy is often per wallet group to enable longer
usage for smart cards and shorter for mobiles, for instance).

Once per time period, it scans the state store for newly registered revocations.

Additionally, if a wallet is in a quarantine group, the wallet may be required
to prove it is not a revoked device.  E.g., for the v0 protocol by producing
a signature with its network access credential using a prior epoch's basename
or a signature with its token transfer credential using a basename of a prior
token.  For the v1 protocol, the split is not necessary.  This should be handled
by its registrar to issue new NACs. The clerk will need to share the basename
linkage from the ticket request or the revocation server will need to share
the basename from the double spent tokens.

(TODO: revocation linkage list enforcement is not yet implemented.)

## TokenMap

TokenMap is a simple database interface which is keyed upon a unique key-id and
contains a list of token-histories. For valid tokens, the list is of length 1 and
the token history reflects the last update from a trim or validate call.

For convenience, TokenMap will also track the necessary revocation data as
it is updated and perform the double spending detection.

All callers of the tokenmap MUST cryptographically verify tokens. TokenMap will
not.

## Validate

Receives tokens, cryptographically verifies them, and then passes them to
tokenmap to update.  There tokenmap applies double spend detection logic.  If
the history extends with validity, the tokenmap is updated and an affirmative
response is returned. If there is a fork in the history or the token history is
truncated, then validation will fail. If a token's initial signing is not from
a mint but from the trim server, then the history will be compared from the
trim entry forward.

If validation fails because of a history fork, then the tokenmap will be updated
with the alternative history in parallel to the other and the forking wallet
will be revealed and labeled as a double spend.

All double spent or invalid tokens will fail validation even if they do not
create a revocation event.  Additionally, once a double spend is detected,
currently all versions of the coin are considered suspect. This policy is
configurable based on the implementation in tokenmap.

## Swapper

Receives a token transferred to its address and returns a new token
transferred to the sender (using the ticket from the transferred token).

Prior to issuance, a call to validate will be made for the token. If all is
valid, then the token will be swapped.

## Recovery

(Not yet implemented)
This server provides two services. A wallet may request re-issuance of currency
that was lost to another wallet by presenting a signed assertion between the
two for recovery and the tokens in question must be expired.  This will not be
implemented immediately.

The second service is recovery from revocation.  If your wallet has been
revoked, in a group or directly, you can submit a signature to a new wallet to
transfer funds to or request 

The protocol has not yet been defined for this.

