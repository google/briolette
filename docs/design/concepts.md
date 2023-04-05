# Design Concepts

Briolette is an experimental framework for researching offline digital currency
designs.

At a high level, the current proof of concept is striving to enable cash-like properties:
  - Direct value exchanges between parties without an online intermediary
  - Transactions settle with near-finality
  - Settled funds may be instantly re-spent
  - Traceability is based on the exchanged coins, not the holder’s identity or
    account
  - Small value transactions are not prohibitively expensive to process

while realizing the benefits of being digital:
  - Direct exchange can be performed online as easily as offline
  - Multiple types of funds may exist in parallel (such as sovereign tokens and
    conditional tokens)
  - Business logic may be attached to transacted funds where limited
    respendability and online intermediation is acceptable 

These goals, however, must be met while also meeting the specific needs of all
users of the system. This document explores possible definition of these needs
and a mapping of how briolette may meet them, largely from the perspective of the
briolette system operator.

Please note that the briolette authors are non-expert across many domains.
Extensive efforts have been made to accurately reflect these hypothetical user
needs and requirements.  We hope cross-industry and community engagement in
this project will help refine and/or adjust these perspectives wherever they
are insufficient or inaccurate.


## High level properties

For a digital value exchange system design to be a viable, trustworthiness must
be an intrinsic property.  For the system to be adopted and used broadly, users
must see it as a reliable means of exchanging value with minimal negative side
effects.  Similarly, for the system to be deployed and backed, the system owner
must trust that the system will not enable unbounded abuse or criminality.

Defining trustworthiness in this context necessarily provides a number of user
and operator facing requirements.  These are bundled into three high level
properties: offline, private, and open.  These properties represent different
requirements depending on the perspective and also reflect properties of today's
physical currency.

For system users, they map as follows:

  - _Offline_ reflects availability. Tokens work anywhere, anytime.
  - _Privacy_ is largely around managing negative side effects before, after,
    or at the time of a transaction.  Neither peers nor the operator should be
    able to easily profile or otherwise track a specific user
  - _Openness_ ensures that anyone can participate with confidence at little or
    no cost to themselves.

For system operators, these same properties resolve differently:

  - _Offline_ is about reliable scaling with manageable costs.  Online
    infrastructure should not constrain transaction scalability.
  - _Privacy_ for the operator is about knowing just enough information to keep
    the system safe.  Traceability and identifiability only as a response to
    abuse, not as a default
  - _Openness_ ensures an operator's tokens are not dependent on other
    entities: avoiding single source dependencies and a system that is
    realizable on open source hardware and software

In addition to these specific mappings, briolette must also provide a selective
set of similar experiences, capabilities, and controls for both users and
operators which are not enumerated here.  More detailed requirements for each
involved entity will be necessary to drive a production-ready design. Some
initial exploration may be found at the end of this document.


## Perspective: Token system operator

The token system operator may be a central bank or monetary authority
interested in creating a robust digital currency (e.g., a CBDC) built on
tokens. In this scenario, the system operator's concerns will likely fall into a
few high-level categories:

  - Control of the token supply and lifecycle
  - Token system security, risk measurement and management
  - Adoption and trust

System features and properties will be mapped to these below.

### Role

The system operator is responsible for setting global policy which governs all
other roles in the system, from mint to digital wallets.  For instance, the
system operator may manage token creation, or minting, directly.  However, they
may also choose to certify different entities to operate as token mints by
delegating the token signing keys to these entities.  Additionally, the token
operator may opt to enable mints for different types of tokens, such as fiat
currency tokens and credit currency tokens, based on the mint signing keys.

Beyond minting, the system operator also determines what makes a digital wallet
eligible for holding their tokens and operates, or delegates operation, of
briolette services to manage system-wide policy and revocation updates.  Any
non-technical delegation is not considered part of briolette itself.

### Control of the token supply and lifecycle

Discussion below will assume the system operator and the mint are the same for
clarity.

Each wallet will have a  set of trusted authorities from which it will accept
tokens.  The system operator will supply its public minting keys for inclusion
in the wallet's trusted configuration. Tokens may only be transferred between
digital wallets, whether in a consumer device or banking infrastructure.

Tokens will be transferred between wallets and remain in circulation until:

  1. A mint-attached, token expiration time is reached.
  2. The token has met, or exceeded, its maximum number of transfers.
  3. The operator has flagged the token (or a signing ticket group) for
     removal, e.g., causing it to no longer validate.
  4. Additional policy restrictions result in online-only exchange.

The system operator may re-issue the same token, resetting its expiration
and/or history, or it may simply issue new tokens.

When tokens have reached one of these conditions, retail or bank wallets will
be expected to swap the tokens, if eligible, for valid tokens.

If a wallet is holding a token that is considered invalid by the token
operator, it is expected that they will attempt to swap the token, thereby
taking it out of circulation.  The operator will choose whether swapping is
possible based on the cause of the invalidity.

#### Splitting tokens

The system operator may allow splitting of tokens.  Splitting is when a single
valued token is partially transferred between two entities.  One entity is the
current holder of the token and the second entity is the recipient of a "split"
token.  From an operator's perspective, this allows the creation of tokens in
the field, but with wallet, peer wallet, and server enforced restrictions on
the value -- which must always sum to the original token value.

The system operator may wish to only have a fixed number of tokens in
circulation, disallowing splits.  Alternatively, splits may be reserved
exclusively for specific value tokens, such as 1.00, to be split into change.
If transactional efficiency is deemed more important than fixed token volume,
then arbitrary splits may be allowed of any token.  For example, this would
allow a single 20.00 token to be split into a token of 12.00 and 8.00.  The
12.00 token may then be split into two 6.00 tokens, and so on.  Unbounded
splits do not mean unbounded token volume, however. Each split operation is a
transfer and splits are limited by the maximum token transaction limit.
However, the token authority may express a different split policies, such as
fixed denomination splits only or a maximum transaction limit on splits, for
instance limiting subsequent splits entirely.

#### Limits on "held" tokens

Tokens themselves will carry both a maximum transaction limit and an
expiration, based on the system "clock" of epochs.  If a token expires, it will
only be accepted by an operator swap service -- not by any other wallets.  This
is also true for any tokens that have reached their maximum transaction limit.
However, short token expiration may not be desirable as it will increase mint
activity and additional work across the system.

Two additional controls exist to limit both the total amount of tokens held
over time and the length of time they may persist. Tokens are bound to the
signed ticket which they were transferred to.  Like tokens themselves, all
signed tickets carry policy tags, such as  expiration.  Ticket expiration
limits non-intermediated, or direct, respend, if the ticket has expired. Tokens
must then be transferred between tickets to keep them valid while offline.
Tokens may carry an additional policy tag, soft expiration, which indicates how
many epochs the token will remain valid after the expiration of any signed
ticket in its provenance.

This allows the mint to create long-lived tokens which may be bound to a
"treasury" signed ticket which also has a long expiration. Similarly, the token
may then be transferred to a bank which also may have a long-lived signed
ticket. At this point, the treasury or bank may hold the tokens until soft
expiration epochs after their ticket expires.  However, once transferred to a
retail consumer, the time will reduce significantly, as retail consumers will
have shorter signed ticket lifetimes than the other entities. (Depending on
operator policy, consumers may have identifiable tickets which are longer lived
compared to unidentifiable tickets -- this is explored later in the document).
Each subsequent transfer cannot increase the time before the token must be
swapped -- it will be the result of adding the earliest expiration time in its
provenance with its soft expiration epoch count.

This dual expiration system allows the mint to create a large number of tokens
which may be held by trusted intermediaries for extended periods, such as
treasuries, "swap" services, regulated entities.  Then, once the token is moved
into active circulation, it sets a much more constrained time limit to curtail
extended retail holding.  We will see later that this also results in
beneficial functionality for the consumer user which balances reduced
disconnected operation with increased reliability -- recovery of lost funds.


### System security and risk

Security, robustness, and risk areas are incredibly rich.  This section will
attempt to cover the most critical aspects, but it is not likely to be
comprehensive (send pull requests! =).

#### Token security

Tokens may only be created by mints.  In the current protocol (v0), this done
by signing the token's first transfer, its "base", with a randomized ECDSA
(P-256) signature. The system operator may choose to add any amount of
information to the token with the knowledge that more data creates more
transactional overhead (e.g., bytes transferred, verified, and stored).

Future concerns around post-quantum attacks against cryptography may be
addressed in future protocol designs.  Retrofitting the current protocol is
possible, but it would increase transaction overhead.  For instance, the ECDSA
signature could be replaced by an inclusion proof in a sparse Merkle tree whose
root is included in the Wallet trust root, via state updates, rather than the
mint public keys.

Beyond minting, tokens are valid only if their entire provenance verifies:
transaction between wallets and associated tickets and tag-based policies.  The
receiving wallet is responsible for validating these aspects to minimize their
risk.  The next section details these needs.


#### Transaction security

Transaction security breaks down along a number of lines:

- Is the peer valid?
- Are the proposed tokens valid?
- Is the peer the intended recipient?

It is also critical to note that the system does not guarantee atomicity on
many axes.

##### Peer validity

Peer validity is determined first by confirming both parties have the latest
global state, as enforced through a required handshake phase which "gossips"
any state mismatch.  This ensures both parties share the most recent
system-wide epoch and secure state information known to them through online
synchronization or other peer transactions.  Then, the token receiver is
validated by the sender using its signed ticket.

To receive funds, a signed ticket must be presented. This does _not_ mean that
the receiver is a certified wallet.  It may be a point-of-sale unit or web
service which accepts tokens but cannot itself transfer tokens.  The signed
ticket must not have expired, be cryptographically valid, as signed by the
operator's ticket server asymmetric key (presently P-256 ECDSA), and validate
against any additional policy tags.

The sender may be validated solely by the cryptographically valid transference
of tokens, discussed in the next section. However, in some cases, the sender
may need to verify their access to funds and ability to participate in the
system.  This may be achieved by allowing null-valued splits.  A null-valued
split transfers 0 value of a given token to the recipient while enabling the
recipient to verify the original token value and proof of possession of the
signed ticket which holds that token.  It does not guarantee the sender will
ultimately transfer those funds. (See atomicity for some discussion on escrow.)


##### Transaction proposal validity

A receiver must determine if the tokens sent to them are acceptable.  The
example transaction protocol in the proof of concept allows the receiver to
accept or reject tokens prior to their transference.  This process depends on
the token validity discussed earlier. The token must be signed by a known mint
and each transaction must be signed using a token transfer credential (TTC) and
signed ticket that received it. The policy tags must also validate.  If so,
the receiver can confirm the token is cryptographically valid and, if received,
will be re-spendable with other wallets.

This check does not assure global validity.  As the system assumes network
partitioning is the norm, transactions do not depend on checking the operator
for global consistency.  This means that there is a risk for any transaction
that a cryptographically valid and policy compliant token has been double
spent.  If a token has been double spent, then there is a risk that upon
deposit with a bank or transfer to an online wallet, the token will be rejected
and deemed invalid.  While this is a risk with counterfeit physical currency
today, it is often possible to scale digital attacks much more cheaply and
easily.

To counterbalance this risk, two avenues exist.  The primary protection is the
reliance on the digital wallets to provide assurances to the operator that they
will:


  - disallow extraction of all stored secret keys
  - only sign a given token-with-provenance _once_

These two assurances disallow double spending.  Wallets will be expected to
implement the remainder of the policy functionality, but that does not mean the
additional functionality must have high levels of assurance as the impact of
policy violations will be much lower.

The second avenue is online validation. The system operator will operate the
validation service which will allow system users to check if a given token, and
its provenance, is globally valid. This will allow users to confirm tokens are
valid before acceptance and after.  With physical currency, merchants may not
discover a counterfeit until they visit the depository and banks may not
discover a counterfeit has been deposited immediately.  However, for high value
currency, both parties often perform validation checks immediately.  The same
model may be deployed here -- risky peer-to-peer transactions may validate
tokens prior to acceptance, merchants may validate their tokens at regular time
intervals or after reaching a threshold amount, banks may validate every token
deposited - but are more likely to do so as a batch process than at
deposit-time.


##### Peer identity

By default, peers are not identifiable in the transaction protocol.  Each will
be known by a limited use signed ticket which contains a pre-randomized token
transfer credential.  The operator will be able to link the ticket to an
ephemeral network access credential (NAC) pseudonym, but not directly link the
wallet and user to a given transaction.  Peers may only deduce information from
token history if they themselves have been party to the token in the past or
know an entity's ticket that has been.

However, there are many retail transactions where the peer identity is
important.  Peer to peer transactions between friends and family benefit,
especially at a distance, benefit from additional assurance.  Consumers
purchasing at a physical store cannot be sure the point-of-sales system is
secure and purchasing online cannot be sure the web server has not been
compromised.  Additionally, depositing tokens with a bank or even swapping
tokens with the operator benefit from a means of securely identifying the peer.

Secure peer identity is possible in two ways.  The first is simply using
long-lived signed tickets.  A "static" ticket can then receive tokens in an
on-going fashion. This can easily be used for sharing with peers and helps
avoid sending funds to misrepresentation of known peers.  Addressing
potentially compromised payment intermediaries is done by adding an additional
identity assertion into the signed ticket.  Namely, the operator may require
merchants to register a "public" identity which results in a fixed TTC
alongside their tax identification or other public information that should be
verifiable by a sender's wallet.  This process would eliminate the ability for
interception attacks to redirect where payment is sent by simply changing out
the receiver's signed ticket.

##### Wallet security and policy control

The token proposal validity section laid out the expectations for a wallet.
Digital wallets serve three primary goals:

  - provide a reliable user interface for the user
  - enforce additional operator policies based on gossiped and network state updates
  - provide strong assurances of key protection and signing enforcement

We will not explore the user interface section.  Trusted input and output is a
very challenging problem which impacts any digital authentication and
authorization system. briolette does not provide a solution to this problem.

Operator policy enforcement and state updates are covered as important business
logic necessary to ensure the user does not accept known bad tokens or violate
any policies on tickets or tokens which may cause them to lose funds, like too
many transfers or not verifying expiration dates.  It is expected that wallets
with secure and insecure environments will perform this work on the insecure
side, for instance in mobile application code.   This is also where desirable
features for users will live, such as enabling escrow or lost funds recovery.
All state updates will be signed by token system operator cryptographic keys
and the shared state becomes the single trusted update mechanism which allows
for key and group key rotation alongside revocation.  (State updates and wallet
features are discussed in later sections.)

The primary security concerns with a wallet are in third area: key protection
and signing enforcement.  To achieve this assurance, briolette depends on steps
which must occur outside of the system.

First, the wallet vendor must submit their wallet solution to a laboratory to
be validated against any protection standards the system operator requires. The
vendor may then take this certification to the system operator and register
network access credential issuer keys and the specific model information of any
of its certified solutions.


The wallet vendor will operate a network access credential registration server
for its wallets.  When a wallet's credentials must be renewed or a wallet does
not yet have credentials, it must contact its registrar. The wallet vendor may
have issued network access credentials in the factory if the wallet is a
standalone device or if the original device manufacturer (ODM) provisioned on
their behalf.  If not, the wallet vendor must have implemented a means for the
wallet to remotely attest that it is the wallet vendor's device.  This
attestation will in turn allow the registrar to issue network access
credentials to the device. It is at this point, additional checks may be made
against the requestor (such as additional user identity collection), but no
additional checks are required by briolette's security design.

The wallet's network access credential is an ECDAA member key. This means that
the wallet may sign anonymously on behalf of any other member of its network
access group.  The registrar may operate one or more NAC groups.  In most
cases, the NAC signature will not be anonymous, but instead be pseudonymous.
This is achieved through the use of ECDAA basenames.  Basenames are an
additional value supplied to the signature which create selective linkage. If
the same NAC secret key signs a message with a basename more than once, those
signatures will be linked together.

Selective linkage is a useful property because it allows enforcement of
uniqueness over signing parties without directly identifying them. This will be
used in the network service access section later in this document.

A NAC is required to interact with most briolette services.  Once a wallet has
a NAC, it may then contact the system operator's registrar to receive a token
transfer credential (TTC).  The TTC is an ECDAA membership much like the NAC
except that there is normally a very small number of active TTC groups at a
time as each wallet must have the TTC group public key in order to verify token
history.  This is because the TTC is used for receiving and sending tokens.
Again, selective linkage is used.  When a token is transferred from one party
to the next, the sender signs the token with a basename of the token's last
history entry's signature.  If the sender attempted to double spend a token
with different receiving parties, then multiple signatures with the same
basename would occur and the transactions would be linkable.  (Note, if the
sender attempts to reuse the same token with the same recipient, it will not be
noticed.  The recipient should track received tokens for the time period the
transference is valid for, both to protect against token replay attacks as well
as to enable resumption of interrupted transactions.)

It is unsurprising that a token being double spent is being double spent by the
same key.  Linkage does not provide additional information.  However, wallets
may be required to perform a signature with the known-bad basename in order to
prove they are not offenders.  This enables misbehaving devices to be excluded
from the system. We have not yet gotten to where and when this might occur.

Once a wallet has a token transfer credential, they still cannot transact.  The
wallet must pre-randomized their TTC a number of times.  These are the
credentials which they may receive, and subsequently, spend tokens with.  The
credentials are sent to the operator's ticketing clerk service.  The clerk
service will require the ticket request to be signed with the wallet's NAC and
one of a number of basenames.  Upon receipt of a signed request, the clerk will
ensure the credentials are legitimate, assign randomized group numbers
(currently between 0 and 32768), select wallet and system specific policy and
encode this in a ticket (or tickets), which it signs and returns to the wallet.
The clerk service will store a mapping between NAC key group and the randomized
group integers in the ticket along with the expiration.

The basename used by the wallet will be the current system operators "epoch",
or update time interval, with up to some number, n, of additions. For example,
if the epoch is 1000 and three basenames are allowed, then the basename may be
1000, 1001, or 1002.  This strategy allows the wallet make up to three separate
requests for tickets which are not linked together.  If the wallet requires
additional tickets in the same epoch, it will reuse a basename and link those
tickets to the prior ticket request.  This has no direct negative ramifications
but will reduce the overall privacy stance for the requesting wallet. It is
worth noting that the ability to request some number of overlapping tickets
linked to different pseudonyms avoids creating a system where all token
provenance is trivially linked to the first ticket fetch of a given wallet.

With signed tickets, a wallet can send and receive tokens securely within the system.

##### Atomicity

Transactions are atomic, but only at a cryptographic level.  A transfer occurs
when a new provenance entry is added to the token which transfers it to a new
signed ticket.  The token must still be transmitted to the peer and must be
shared (e.g., validated) with the operator for global consistency to be
achieved.

As explored earlier, assurance against double spending is a combination of the
wallet's security assurances, current system-wide state, and the system policy
configuration. The ability to tolerate network partitioning while maintaining
availability creates a tradeoff in consistency which the overarching system
design attempts to manage.

That aside, there are cases where the above guarantees, both in the wallet
stack and in atomicity, are insufficient. For higher valued transaction, it is
expected a trusted third party would be engaged.  However, there are many cases
where a simpler deposit and escrow situation can be resolved without an active
intermediary.

An operator may enable a transfer tag which allows an offline transfers to
arrange online passive intermediary-based, or escrow, settlement where an
additional party is not needed (e.g., for a secondhand purchase, not a real
estate transaction).  The operator may add an escrow tag. The sender would send
a token with a split value tag and escrow tag.  The split value would leave
the sender holding the remaining valued token which is unconstrained and the
receiver holding a full value token with an escrow tag.  In this arrangement
no other wallets will accept transference of the escrow "deposit" token except
the original sender or the operator's swap service.  The escrow tag will set an
expiration time on the arrangement.

To finalize the transaction successfully, the sender will transfer the other
portion of the split to the recipient. The recipient will then perform a swap
of both tokens together to the swap service which will return tokens that sum
to the total transaction value.  The second token is included in the swap to
confirm the sender finalized.  It is also possible for the recipient to
validate the received split and then only swap the escrow token, as the swap
service will be able to confirm the provenance of the split as the tokens share
a root identity (token base signature).

To abort the transaction successfully, the sender may transfer the escrow split
back to the sender's original ticket. The sender may then swap the escrowed
token for an unencumbered token. The swap service merely confirms the current
holder was the holder which added the escrow tag -- the split token is not
needed as confirmation.


#### Network service access

As described in the section on wallet security, network services are not open
for general access.  All services may required a NAC signature with a rotating
basename.  This is used to keep wallets from accessing network services too
frequently for intentional or unintentional reasons. As there may be a very
large number of wallets in use, it is important to provide denial of service
management mechanisms in the core platform.

It is expected that the basenames will be deterministically derived from the
current system operator epoch such that wallets can compute them prior to
accessing the service.  This provides a means of limiting the number of
(unlinked) accesses per wallet while avoiding privacy violations on accident --
through accidental or intentional basename reuse.


#### Token abuse detection

Token abuse may be categorized along the same lines as well as security: (1) a
violation of signing restrictions, or (2) failure to enforce a policy.  While
failure to enforce a policy may be detected by a future recipient of the token,
this section is focused on the capabilities afforded to the system operator.
In particular, the system operator cannot detect what it does not have
knowledge of.

The system operator learns about token provenance updates through calls to
validate tokens and swap them.  Validation calls are not a required operation
for wallets, but most larger entities, such as banks, will validate any
holdings.  Beyond this, scheduled validation calls may be added as normal
features for wallets, especially as a lost funds recovery feature would depend
on it.

Swaps, however, are not optional.  Calls to the swap service will be driven by
ticket expirations, token expirations, and token provenance length limits.
This allows modeling using time-based estimation as well as transaction-based.
The selection of expiration dates, as well as any additional policies, will
allow the operator to manage the boundaries of updates.

In the proof of concept, the tokenmap stores the known history for all tokens.
To detect double spending, the operator must operate a service like this.
There is no interdependence between tokens, however, so any such system shards
very easily.  Tokens may be indexed using their unique minting signature (over
the token base).  The history alongside any additional metadata may be stored,
such as if a split has happened and has already been validated.  This allows
the operator to check any supplied token, via validation or swap, if it matches
the known provenance, is a subset of it, or is a superset.  If it is a superset
and is cryptographically valid, then the tokenmap is updated.  If there is a
fork in the history, then the operator may extract the key pseudonym having
detected a double spend.  The only valid fork is if a split is allowed -- but
splits do not require the single signature invariant to be violated.

Double spending abuse is the primary concern of briolette.  However, there may
be other forms of token abuse which should be considered and added. For system
abuse beyond tokens, please see the enforcement section below.

While detection has been characterized as an operator problem, detection of
misbehaving peers is of concern to any participant in the token system.  This
detection is possible through the wallet-side enforcement mechanism and is also
discussed in the next section.


#### Abuse and policy violation enforcement

Detection of double spending or abuse of the network services or even
participation in a criminal enterprise are all reasons that an operator may
wish to exclude a wallet from the system or attempt to identify the holder of
the wallet which performed a given transaction.

Enforcement in briolette is hierarchical.  If an operator believes a full
wallet model compromise has happened due to a double spend -- such as a
critical, exploitable vulnerability in the secure environment -- then the
operator may make changes for every wallet device.  At the extreme, all devices
could be excluded by revoking their network access credential group.
Alternatively, wallets from that NAC group may be required to perform an
additional "test" at their nt ticket request, where they perform a TTC
signature using the double spend basename, to prove that they are or are not
the misbehaving device. If the misbehaving device appears, then the operator
can message the wallet requesting in-person presentation of the device.  If
not, additional tickets may be granted.  If all wallet devices require an
upgrade, then their NAC group may be revoked and they must then revisit their
NAC registrar to prove they have received the update and can be issued a new
NAC.

Beyond TTC and NAC revocation options, the system supports global state
updates.  Wallets will be expected to synchronize regularly, with the service
or with peers, to receive secure (P-256 ECDSA signed) updates from the
operator.  The updates contain the trusted group and ECDSA public keys as well
a bitfield of "revoked" groups.  If a ticket is presented to a wallet from a
revoked group, it will not accept the transaction.  When the operator detects a
double spend, or other violation, it will look at the ticket clerk's mapping
from signed ticket-to-group number for the specific offender, or for all groups
for the given NAC group.  It will then update the global state, at the next
epoch or sooner, to include the revoked groups in the bitfield.


This approach provides a considerable amount of flexibility to the operator.
For instance, if an operator can identify a transaction that is deemed
unacceptable, then it may use the basename and the ticket clerk to force a test
to catch the offender.  The effort will not be secret, as every wallet with the
same NAC will be challenged, and it is possible for a wallet to track, up to a
point, all basenames it has ever signed.  This means that an intentionally
misbehaving wallet may avoid future detection, but it will be excluded from the
token system entirely.


#### Risk management and higher level policies


The prior sections have provided a view on how briolette enables operators to
manage their risk envelope through policy configuration and enforcement
mechanisms.  It is expected that these approaches should be modeled and
simulated in order to help operators understand the expected mean time to
detection of double spend as well as the mean time to revoke.  The specific
simulation data and modeling will be deployment specific.

Beyond the discussed policies, there are many others that may be considered.
The two most commonly discussed are requirements around legally identifying
users, Know Your Customer or KYC, and transaction velocity limits.

Both of these extensions are possible.  While briolette does not benefit from
identifying human users, it is possible to add user identification at either
the NAC issuance stage or via a specialized ticket issuance.  Namely, the
ticketing server may allow a request which carries with it an out of band KYC
assertion. If the ticketing server can verify the assertion, it may issue a set
of tickets with a KYC tag.  These tickets may then be used for any transactions
which require KYC without directly connecting all tickets to the unique wallet
or legal identity of the user.

Transaction velocity cannot be trivially enforced between peers in briolette.
However, the operator will be able to detect velocity violations server-side
and use the enforcement mechanisms to exclude the abusive device.  For
instance, if each issued ticket has a maximum spend tag, it is trivial for the
tokenmap to create an index on signed tickets and validate when transaction
sums are exceeded.

### Adoption

Adoption of any new technology or change is always a challenge. There are a
number of aspects of briolette which may facilitate adoption across a few
challenging areas:

  - Operational costs
  - Availability
  - Viability
  - Reliability
  - Privacy

#### Operational costs

Operating any form of real-time settlement system will have costs which scale
with the number of transactions in a given time period.  From reviewing public
data, it appears that many real-time payment system costs scale at a
superlinear rate with transactions.  Those systems that limit the maximum
transactions also effectively manage their costs.

In this system, transactions will be validated by the token system operator, or
its delegates, but the transaction processing time is not in the transaction
settlement path.  Transaction settlement occurs directly between wallets, with
near-finality like physical currency.  This enables transactions to proceed
even if there is a complete system outage.  Additionally, briolette is
conducive to both batch validations and extensive sharding.  Transactions are
validated per-token and this will occur via the validation service or the swap
service.  The processing can be offloaded to a storage and compute shard
dedicated to that token and its immediate neighbors -- where the neighbor
definition can be tuned arbitrarily based on performance data.  In the
situation where retail merchants and private banks perform bulk validations,
the real-time response is not require and, traditionally, batch processing is
more efficient than per-request processing.  (In the simplest of cases, it is
less costly because there is less communication overhead.)

These features do not mean operating a token system is cheap or free. It shows
that this system design enables high system availability without requiring high
service availability and the costs that come with it.

#### Availability

From a retail user perspective, it is a goal of briolette to be always
available, like physical currency.  A transaction requires two valid wallets
with valid signed tickets. There is no dependency on an Internet or cellular
connection.  Additionally, retail users may re-spend any received tokens. This
allows users to realize the value of their prior transaction immediately.

The window of availability, however, will be dependent on the policies set by
the token system operator.  These policies may even vary by wallet solution.
For instance, a smart card-based design may receive longer-lived tickets than a
mobile device-based wallet.  If these discrepancies ist, it will be important
that wallets effectively communicate availability expectations to users as any
negative surprise will impact trust and adoption.

#### Viability

The v0 protocol depends on cryptographic algorithms which have been implemented
in secure hardware already.  In particular, elliptic curve direct anonymous
attestation can be built against trusted platform modules (TPMs).  TPMs often
share the same silicon underpinnings as other secure elements, and other
research has shown support for pairing-based elliptic curves being used
successfully in java card environments.  Unfortunately, many of these examples
highlight software, not hardware, API limitations.  As such, it is likely that
any token system operator that wishes to realize a system like briolette on
smart cards, SIM cards, mobile platforms, or similar, will need to work with
secure environment operating system providers to evolve the API on top of
existing hardware.

It is possible for briolette to be built and deployed with no secure
environment support, but doing so would leave the wallet software provider as
the assuring party to the token system operator.  As such, the wallet vendor
would need to invest in their own mechanisms to offset any risks they may be
taking.  For instance, a wallet vendor may require a direct relationship with
the wallet holder to enable risk offsetting or limiting future abuse.
briolette itself is not built around similar systems to avoid good actors with
compromised systems for being penalized.  As such, any low assurance wallet
platforms be more useful when used with very tightly constrained ticket
policies, such as a short expiration time or for specific delegation, such as a
web browser transferring tokens on demand to one of a few destinations, rather
than as a general purpose wallet.  This is a space which would benefit from
additional exploration.

#### Reliability

Much like availability, retail users will expect to be able to realize the
value of tokens they have received.  If a user discovers that they have a
double spent token, thee  token system operator will be able to decide if they may
be compensated for the loss.  In many currency systems today, retail users are
not compensated if they discover they have received a counterfeit note.  This
system does not improve on that situation but may provide additional tools to
allow a better situational assessment by the operator than is possible with
physical currency.

Beyond double spending concerns, many consumers worry about digital wallet loss
resulting in token loss.  The combination of token soft expirations and ticket
expirations allow for consumers who have validated their holdings to recover
lost tokens after the soft expiration has expired.  This will allow the system
operator to confirm the tokens have not been validated within the wallet
enforced policy timeframe and show that the tokens were last known to have been
in the claimed lost wallet.  An additional service or system will need to be
put into place to anchor the ownership claim of the lost wallet.  This may be
done either through the NAC registrar or through the addition of a new protocol
method which allows a wallet to sign a message indicating that another wallet
is allowed to perform a recovery.

#### Privacy

This system does not assert a specific privacy opinion, but instead attempts to
follow physical currency where possible.  The primary difference is the
transaction history associated with each token.  While it is possible to build
a transaction graph for physical currency, it is requires each participant in
the graph to participate and then share their information with the currency
system operator.  This is not easy nor is it available, by default, at a global
system level as it is with a digital system.

With physical currency, counterfeiting is made difficult through the complex
substrate the currency exists on.  For digital currency, counterfeiting takes
the form of double spending because it is intrinsic that a perfect copy of the
original token can be made.  As such, it can be made more difficult using
secure hardware, as with the physical currency anti-counterfeiting substrate. In
that case, instead of the secure substrate being passed between users, the
token is passed between secure substrates.  The transitive nature of the binding
between token and substrate mean that the token system operator would have no means
of detecting and responding to double spending without also having a mechanism to
detect when a given substrate has been compromised. For physical currency, a
compromise in the substrate can be analyzed when the counterfeit currency is
found.  This difference is why each token carries with it information about the
secure substrate it was bound to in the past.  As this is new compared to
physical currency, this system attempts to remove uniqueness from the history,
instead focusing on the substrate vendor as public knowledge to the token
system operator as well as the ability to exclude abusive substrates, or
wallets, from future transactions.

This balance is attempted using the randomized credential and randomized ticket
group approach.  Together both enable peer transactional privacy, and with the
addition of random self-transfers, resistance to analysis by common sources and
sinks in a retail ecosystem, such as a bank or payment intermediary.  The
result is that the average user will not be identifiable to peers and the
system operator will have limited means for identifiability without losing the
means to respond to abuse.  For instance, if a token transits long-lived
identifiable signed tickets, such as a private bank and later a merchant, the
operator will be able to draw conclusions about the wallet user between these
transactions while also knowing which NAC group the wallet is a part of.
However, without further information from the other entities, there will be no
clear linkage (excluding any KYC-enabled tickets) to the wallet's or user's
identity and any additional transfers between those two transactions will
further reduce certainty.

This approach to privacy is meant to achieve similar retail properties to
physical cash while deriving the largest benefit to all parties from the tokens
being digital.


## Detailed theory of operation

See the [theory of operation](theory_of_operation.md) for service-specific details.

## Detailed requirements exploration

To guide the design work, a number of requirements were extracted from how
physical currency operates as well as from expanded research.  The findings are
reflected below.

### Tokens

Tokens have a number of requirements and expectations, much like currency
itself:

  - Must carry a value
  - May have a unique serial number or other unique identifier, such as unique
    signature
  - May have a type, class, or other encumbrance. (E.g., conditional tokens)
  - Must have cryptographic assurance over the above metadata which cannot be
    created except by, for example, by the monetary authority’s mint.
  - Must have a digital version of “anti-counterfeiting substrate”,  such as
    polymer substrates with security features, which the metadata is bound to.
  - Must only have value when bound to the anti-counterfeiting substrate
  - Must contain no secret information; notes may be stored in insecure
    locations
  - Must be able to be exchanged directly between “wallets” without an external
    intermediary
  - Must be able to be exchanged remotely with assurances of the recipient


### Wallet Stack

The wallet stack refers to the hardware/software environment that enables
participation in the system:

  - Must have a validated, secure (criteria TBD) cryptographic subsystem which
    enables
    - Certification to a remote wallet authority, operated on behalf of the
      monetary authority, to register for participation in the system
    - Enforced signing restrictions for keys and data (e.g., to limit double
      spending)
    - Protection of private key matter from exfiltration
  - May have an unprotected user interface
  - Must be able to be held accountable for assurance failure
  - Must be able to be deployed on existing systems and changes to those
    systems for future performance should be anticipated

SIM cards, mobile phones, and payment cards must all be considered in this design.


### Consumer Wallet User

A consumer wallet user will also have a set of expectations and requirements
that may overlap with the set of “must not”s from the operator but also are
relevant to creating a physical cash-like solution:

  - Must be able to spend and receive money with or without an Internet
    connection
  - Must be able to purchase goods and services in person
  - Must be able to purchase goods and services online
  - Must be convinced that the sender of funds will send funds that they can
    then realize the value of (respend or deposit).
  - Must be able to give funds to individuals regardless of banking status or
    digitized identity – from their own children to giving cash gifts to
    friends and family to tipping a busker or paying someone on the spot for ad
    hoc service
  - Must not have require their transactions linked to their legal identity
  - Must not have their transactions linkable across businesses or people by
    those businesses or people.
  - Must not be held accountable for failures in the wallet stack. (E.g.,
    malware abuse of their wallet is not the end user's fault)
  - Must be able to withdraw money from their bank and spend it at a store
    without the system operator being able to tell they performed both
    transactions without confirming with both counterparties out of band.
    E.g., asking the bank who withdrew the money should not be enough.
  - Must be able to confirm a merchant is a merchant before completing a
    transaction – especially if online.
  - Must be able to give out a static “address” to receive money at (e.g., from
    a friend or family member which is not local).
  - Must be able to send funds without an interactive session if the
    destination “address” is known.
  - Must generate a receipt for every transaction
  - May be able to pay for value-added services which enable purchase disputes
  - May be able to send a proof-of-funds, or proof-of-funds-and-hold, message
    prior to an in-person purchase, such as on the secondary market.
  - Must be able to withdraw and deposit funds from their bank remotely
  - May provide a means to recover money from a lost wallet
  - May be able to linkable and unlinkable identity attributes for a subset of
    transactions. E.g.,
    - May be able to enable one-sided or two-sided KYC for transactions at a
      specific threshold
  - May be able to coordinating with digital identity assertions allowing
    unlinkable, anonymous over-<age limit> assertions for restricted item
    purchase (such as alcohol).


### Merchant Wallet User

A merchant is any counterparty selling a good or service as a business –
whether it is a single person or a large entity, whether it is online or
in-person.  A consumer user may also sell goods or services, but their status
as a merchant will depend on the laws and regulations of their jurisdiction.
We will consider a merchant as a “registered” business for these purposes,
though these expectations and requirements may also be relevant to the consumer
wallet user:

  - Must be able to provide a fixed, or static, address to enable single
    directional payments (e.g., QR code, online payment address)
  - Must be able to provide a fixed address to enable quick discovery of
    payment devices (e.g., QR code)
  - May be able to provide a fixed address certified by the system operator
    which links the address to the business cryptographically (and ideally in a
    human readable way).  This is intended to provide additional assurance
    against point of sales or online malicious-in-the-middle-style attacks.
  - May provide tax identification disclosure in receipts for the consumer and
    linkage to the system operator to see funds received at a merchant address.
  - Must be able to delegate funds acceptance to frontend webservers or
    point-of-sales units without giving access to the keys necessary to spend
    those funds, even if the point of sales units have their own wallet stack
    keys and funds for giving change.  (E.g., enable a finer grained flow
    control of money in and out of cash drawers at a register or ensure a
    compromised webserver can’t easily transfer all funds to a third party.)
  - Must be able to reuse incoming funds for future transactions without
    depositing or withdrawing from the bank.
  - Must be able to receive and transfer funds without connectivity


### Commercial Bank Wallet User

Commercial banks are the frontline for many users in accessing the cash
economy.  They are also expected to carry reserves in cash. These two
properties result in additional requirements for the system:

  - Must be able to create wallets which enable complex authorization schemes,
    such as multi-party authorization
  - Must be able to receive money digitally at bank branches, ATMs, or online.
  - Must be able to send money digitally at bank branches, ATMs, or online
  - Must be able to integrate wallets with existing banking core systems (e.g.,
    from FIS)

### System Operator

While the system operator is often the same entity as the owner, we separate
the operational requirements that apply to the design for clarity:

  - Must be able to detect double spent coins in the system
  - Must be able to detect which wallet stack allowed the double spending
  - Must be able to quarantine wallet stacks
  - Must be able to update trusted keys in wallets
  - Must provide a means for legitimate users to access their coins in the
    event of abuse of a similar wallet stack (quarantine)
  - Must not provide a means to identify and track a single wallet stack in the
    system
  - May be able to revoke a specific double spending wallet
  - Must not be able to revoke or identify a single wallet stack without double
    spending or an out-of-currency system means of identifying the wallet stack
  - Must not need to store wallet stack identities to operate the system safely
  - Must not need to store wallet stack mappings between people and wallet
    stacks to operate the system safely
  - Must not be need to be able correlate people to wallet stacks without
    additional information (e.g., explicit KYC, asking a bank who withdrew the
    funds) for safe operation
  - Must not be need to be able to confidently assert if the same wallet stack
    withdrew funds and then spent those funds for safe operation
  - Must provide a mechanism for abused systems to be recovered or at least
    analyzed
  - May allow verifiable programmable endpoints or the addition of encumbrances
    to transactions (but should avoid introducing fragility at all costs)

### System Owner or Authority

The system owner, such as a central bank, is ultimately responsible for the
overall system.  They may or may not also operate the system.  As the system
owner, there are a number of different objectives by the design at a high level
which were discussed in the perspective section above.


