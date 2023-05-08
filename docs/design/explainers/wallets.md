---
title: Wallet Overview
description: A walkthrough of briolette wallets
author: Will Drewry
keywords: briolette,ecash,cbdc,se,smartcard
url: https://github.com/google/briolette/docs/designs/explainers/wallets.md
transition: pull
---

# Briolette Wallets

A quick overview

---

## What is a wallet?

- A wallet is a combination of hardware and software that a user may rely on to send and receive tokens within a briolette system


---

## What hardware makes up a wallet?

Wallet hardware must

- provide accelerated, isolated cryptographic operations and secure storage
- For the current cryptographic protocols and algorithms
  - Elliptic Curve Direct Anonymous Attestation, with specific curve support
- Key generation
- Operation access control
    - Primarily to disallow double-signing of token transfers within a validity window
- Secure storage of private key matter
- While dedicated hardware is not necessarily required
  - it provides a strong set of assurances to the system operator
  - and avoids solutions which provide non-technical assurances
    
---

## What software makes up a wallet?

Wallet software must

- implement all transaction and service protocols
  - manage token storage and wallet state
  - fetch system state and tickets
  - renew or swap tokens near expiration or transfer limits
- implement form factor specific interaction protocols (NFC, BLE, TLS, etc)
- provide a user interface for token and wallet management
  - transactional authorization will be critical to the user experience

---

## How is a wallet enabled? (1/2)

- Wallets must be provided by a vendor which the operator trusts
- Each wallet will go through a number of steps at setup
  - The wallet will prove it is a valid vendor wallet to the vendor
  - The wallet will generate a private key and send the public key to the vendor
  - If the wallet validates, the vendor will issue a network access credential (NAC) for the wallet's key
  - The vendor (and/or the user) will supply other configuration for the supported briolette systems

---

## How is a wallet enabled? (2/2)

- For every briolette system the wallet will operate with,
  - the wallet will use its NAC to request a token transfer credential (TTC) from the operator
  - once issued, it will then use its NAC and TTC to request transaction tickets
- With a TTC and tickets, the wallet is ready for transacting

---


## How does a wallet prove it is valid to its vendor?

- This process is curently up to the vendor, but standardization is encouraged.
- There are many possible approaches:
  - The vendor may embed a secret key in the wallet's hardware which is used to "attest" to its validity
  - The vendor may rely on a secret key installed after an in-person, or other, process which is then used to attest
  - ...
- Similarly, preparation for the arrival of post-quantum cryptography needs may set additional requirements
  - such as the addition of a shared symmetric secret or other PQ-resistant fallback

---

## How does a wallet vendor become eligible for any given operator?

- At present, there is no guidance.
  - It is expected that protocol and API standardization will guide baseline conformance
  - Secondarily, laboratory-validated standards, like Common Criteria Protection Profiles, may provide assurance of hardware and software properties
- Once a vendor has met the criteria, they will register multiple NAC group public keys
  - Credentials issued to the wallets will be validated against these prior to allowing access by the operator

