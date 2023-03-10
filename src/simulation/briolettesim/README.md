# Briolette System Simulation

This system demonstrates an initial system design for Briolette.  This systems
allow currency to be traded between consumers, merchants, and banks without any
direct involvement from the currency operator.  The operator mints currency and
operates several online services.  The operator provides a registrar for
enabling new wallets, a ticket granting service which allows wallets to
continue to transact, a revocation service which allows counterfeits and
counterfeiters to be quarantined, and a currency history validation service.


# Entities and events

## Event design context

To faciliate distribution of computation, all operations are resource-oriented.
Namely, if a resource is being added to by an agent, an agent may generate an
event which includes it as a source and the resource containing agent as the
destination, be it the World, View, or another agent.

If the agent needs to receive a finite resource, it is not possible to generate
consumption events which guarantee atomicity.  For instance, if a bank agent
has $100 and a user agent emits a withdraw(from:bank, amount:100) event along with
five other agents, then each agent will receive their $100 when they apply their
events, but the bank will be overdrawn.

To accomodate this computation model, withdrawals, or other finite resource
acquisitions, must be requested by the receiving agent such that they do not
receive it until the next step via separate events.  Alternatively, the resource
holding party, such as the bank, may opt to distribute resources based on its own
decision process.

## Entities

Every entity in this system is modeled as an agent, the world, or the population.

The "World" is the source and sink for all online activity to avoid creating ISPs
as additional agents in the system.

The current "View" is the neighborhood of the agent.

Agents may be one of:
- Retail Consumer
- Retail Merchant
- Online Merchant
- Commercial Bank
- Monetary Operator


Retail consumers and merchants exist in a simulated 2D grid environment,
initially placed randomly.  Movement between grid spaces is modeled using the
Levy distribution (TODO) for consumer. Merchants do not move at present (though
a certain class of merchants should move!).

Banks will also have a fixed location, but may be accessed via the Internet by
merchants or consumers wishing to deposit or withdraw funds.

The operator will exist online only until new operations are introduced which
require in-person usage (e.g., Wallet reset/recovery).

## Events

- Wallet events: Register, Synchronize, Validate, Transact, Gossip, RequestTransaction, Trim
- Consumer events: Move, Depart
- Operator: UpdateEpoch, GrantTickets, UpdateStatistics
- Population: Add, Del

### Wallet Register
   * Name: Register
   * Source: Agent
   * Destination: World (Operator)
   * Parameters: wallet id: unsigned integer

A call to register allows a consumer to activate their wallet. In this model,
registration in included to ensure we accurately estimate the total service
needs. When a new consumer arrives, they will call Register before anything
else and they will be assigned a "group number".

When a double spender, or counterfeiter, has been revoked and is rejected from
a certain number of transactioins, they will call Register to create a new
wallet (in practice, on a new device). This will make them a normal consumer
unless they can find a way to double spend again. (Intent value versus
opportunity value.)

### Wallet Synchronize
   * Name: Synchronize
   * Source: Agent
   * Destination: World (Operator)
   * Parameters:
       * wallet id: unsigned integer
       * last\_epoch: unsigned integer
       * tickets_requested: unsigned integer

This is called by wallets at some interval to fetch the latest system
information (secure timestamp, revocations, new keys) from the operator.
Additionally, this call provides transaction tickets, if needed. 

It is also possible that synchronization will return recommended behaviors.
For instance, if a higher than normal volume of counterfeiting is occurring,
the sync state may specify a specific coin value threshold for validation
before acceptance or a recommended validation or synchronization frequency
change.

Tickets are returned via a GrantTickets event. In ABSim, world events are
generated after agent events have been collected. This will allow tickets to be
granted in the same step that Synchronize is called. (World events are not distributed.)

### Wallet Validate
   * Name: Validate
   * Source: Agent
   * Destination: World (Operator)
   * Parameters:
       * wallet id: unsigned integer
       * coins: Vec[coins]

This is called by wallets when they wish to verify that the history, or provenance, of the
presented coins is known or builds on a known valid history.  The operator will
track coins and coin histories as they are presented to the validation interface and this mechanism
acts as the primary means to discover counterfeit coins.

Participants are incentivized to use this interface in two ways:

   * Coin validity:
       * Merchants may validate larger transactions or coins prior to acceptance.
       * Consumers are incentivized to validate in the case of peer-to-peer transactions with unknown parties (auction, marketplaces).
       * Banks will validate after deposit as they may then return counterfeit currency to a dedicated Operator wallet.
   * Coin recoverability:
      * Consumers may be able to recover coins which were last known in a specific wallet after an operator specified time.


#### Sidenote: Coin Recovery
Recoverability is not included in this model, yet.  Recoverability requires a means
for the consumer to prove lost wallet ownership which will likely be done by
escrowing the internal wallet state encrypted to an operator, or regulated
entity's, encryption key, and wrapped by a user secret, be it a knowledge
factor or backup wallet.  E.g., users may keep backup wallet proof on all their
devices, with their cloud provider, or across devices owned by family or
friends.

### Wallet Trim
   * Name: Trim
   * Source: Agent
   * Destination: World (Operator)
   * Parameters:
       * wallet id: unsigned integer
       * coins: Vec[coins]

If a coin's history becomes too large, its history must be trimmed. If a coin is valid,
then the operator will return a new history originating with the operator transferring directly to
the wallet id that was already holding the value. (If this turns out to be impossible, then
the wallet will transfer funds to the operator and they will transfer back new funds.)

If the coin is invalid, a trimmed history will not be returned. In the real
system, a well behaved wallet would turn in the counterfeit coin by
transferring it to an operator wallet.  The receipt of transfer may then be
used to attempt reimbursement, etc as dictated by operator policy.  (E.g., with
KYC via a regulated entity, it may be possible to receive reimnbursement using
the receipt up to some threshold per person and per counterfeiting source.)

If the wallet is not well behaved and the coin is not transferred to the
operator, then it may continue to be circulated until its history length is
unacceptable to any other wallets.  Additionally, if the counterfeiter is
revoked, the coin is likely to be rejected as more wallets receive the updated
state.



### Wallet Transact
   * Name: Transact
   * Source: Agent
   * Destination: Agent
   * Parameters:
       * wallet id: unsigned integer
       * coins: Vec[coins]

Coins are transmitted from the source agent to the destination agent if the
destination agent has not been revoked. Additionally, the current global state
will be synchronized as a pre-requisite of the transaction completing.

If either the source or destination has been revoked, the transaction will
fail. Where possible this failure will occur in the event generation phase
which will allow a StatsUpdate event to be emitted rather than the Transact()
event.

### Wallet Gossip
   * Name: Gossip
   * Source: Agent
   * Destination: Agent
   * Parameters:
       * epoch: unsigned integer

If either party is out of date during the generation of a transaction event, a gossip
event is emitted with the most recent update of the two. In practice, this will occur
via a pre-transaction handshake between the transactors.

### Operator UpdateStatistics
   * Name: UpdateStatistics
   * Source: (any)
   * Destination: World
   * Parameters:
       * StatisticsData Struct

Any agent or operator may generate an updatestatistics event. This will contain
a struct of unsigned integers which track events throughout the system, such as
transactions rejected, etc. The operator will pick this event up and update the stats
which will be available to the ABSim manager observer.


### Operator GrantTickets
   * Name: GrantTickets
   * Source: World (Operator)
   * Destination: Agent
   * Parameters:
       * wallet id: unsigned integer
       * tickets: Vec<Tickets>

The operator creates this event after a call to Synchronize requesting non-zero
tickets. It provides tickets back to the requesting agent, if their wallet id
is valid. In practice, the wallet identifier is not disclosed to the operator.
Instead a proof of wallet certification is blinded and presented and the
operator can decide based on if they can unblind (a proven bad wallet) or on
the associated group information.

### Population Add
   * Name: Add
   * Source: World
   * Destination: Population
   * Parameters:
       * AgentDescriptor struct
       * count: unsigned integer

Based on an arrival rate (Poisson), new consumers enter the system. This event
causes them to be added.  (Not yet impl)

### Population Del
   * Name: Del
   * Source: Agent
   * Destination: Population
   * Parameters:
       * agent id: unsigned integer

This event is triggered by an agent after it has "lived" a certain number of steps.  After an average wallet lifetime, a Del event is sent and the consumer is removed from the system.
(Not yet impl)


# User journeys

The events don't describe the whole story.  We can stitch them together with the agent's journeys.

Merchants have a limited number of journeys at present:

   * Come online and register [implemented]
   * Receive money [implemented]
   * Validate money and/or deposit with their bank at intervals.

Consumers have more journeys:

   * Determine how many transactions they will attempt per step-period.
   * Transact multiple times in one period
   * Come online and register [implemented]
   * Go bad and increase double spend frequency
   * Get some currency and hold it for a while
   * Move around [implemented]
   * Withdraw money [implemented: RequestTransaction, Wait, Transact]
   * Spend money with a merchant (local) [implemented: still needs revocation detection]
   * Spend money with another consumer (local) [implemented]
   * Deposit money
   * Receive money
   * Synchronize and get new tickets [implemented]
   * Attempted to transact but detect bad peer or risky currency
   * Get rejected and stop transacting (double spender)

These journeys then need to be configured based on profile: tourist/traveller
vs local as it changes daily transaction volumes dramatically. Also regional
expectations, such as going to multiple food vendors in one market versus
paying one restaurant for a meal.

Bank journeys:

   * Fund [implemented but manually at init]
   * Consumer withdrawal [implemented]
   * Merchant deposit [implemented]
   * Validate funds with operator [implemented]


The system must also capture specific money journeys. While they should be
covered above, they should be drawn out as well.

## Profiles and dynamic discovery

In order to effectively add online transactions and model multiple user
journeys in parallel, the system will need to move beyond grouped consumer
settings and merchant settings to having typed agents request configuration
at initialization.  This will allow randomized roles to be easily assigned out,
from tourist to office worker to food truck, for instance.  Additionally,
a query functionality will be necessary to allow agents to configure their banks
and select the right online vendors based on their profile.

