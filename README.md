# Briolette - experimental framework for offline-enabled digital currency

Briolette is an experimental framework for researching offline digital currency
designs.  This project is a proof-of-concept only and does not reflect a
completed system nor a finalized design.  Its purpose is solely for
research and experimentation. This is not an officially supported Google
product.


## Overview

At a high level, the current proof of concept is striving to enable cash-like properties:
  - Direct value exchanges between parties without an online intermediary
  - Transactions settle with near-finality
  - Settled funds may be instantly re-spent
  - Traceability is based on the exchanged coins, not the holder’s identity or account
  - Small value transactions are not prohibitively expensive to process

while realizing the benefits of being digital:
  - Direct exchange can be performed online as easily as offline
  - Multiple types of funds may exist in parallel (such as sovereign tokens and conditional tokens)
  - Business logic may be attached to transacted funds where limited respendability and online intermediation is acceptable 

There are a number of features that make up briolette's core design:
  - The cryptographic protocol can evolve – it must provide a set of core functionality to the surrounding system and be realizable on existing hardware, if possible.
  - Detecting and revoking double spenders is scalable – revocation can occur at different points in the system which enable hierarchical revocation capabilities.
  - Offline and online are one system – by creating one system with direct exchange, system operation controls and incentives create one large scale system to reason about, not two.

Every "wallet" carries a private secret which can have its public portion, or
credential, randomized.  Transference of tokens depends on valid
credentials which are locked in, or committed to, by the prior holder of the
token upon transference.  The prior holder must transfer the token using the
credential that they themselves received the token on.  This creates a
verifiable chain of history between these random credentials that are not
directly linked to the participants.  The credentials themselves have
controlled linkability which provides different privacy properties from
transactional and global system perspectives.  The current prototype is built
around ECDAA, using [this](https://github.com/xaptum/ecdaa) implementation. 
Further research on the underlying crypto approach under way to improve on
ECDAA.

See the [theory of operation](docs/design/theory_of_operation.md) for a more
detailed design discussion.

## Building

### System dependencies

Your system will need to have the [Rust](https://www.rust-lang.org/) programming language installed -- version 1.68.0 or newer.

Additionally, see
[xaptum/ecdaa](https://github.com/xaptum/ecdaa/blob/master/doc/BUILDING.md) for
any system requirements for building AMCL or ECDAA, such as libtss2.


### Building

The easiest way to build is to use the utils.sh bash helper:

    cd src
    source utils.sh
    build_external
    build

## Running

If you are using utils.sh, simply run

    start_servers


This will start all the servers in an order that ensures all data creation
occurs in the right order. Additionally, it will perform one 2 token
transaction.

## Simulation

src/simulation/ carries a simple simulation system. To build:

    cd src/simulation/briolettesim
    cargo build

To run:
    ./target/debug/briolette-sim

All scenario configuration is currently hard-coded.

## Contributions, etc

Please see [docs](docs/) for details.
