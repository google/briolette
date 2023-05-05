---
title: Briolett Explainer
description: An introductory explainer of briolette
author: Will Drewry
keywords: briolette,ecash,cbdc,se,smartcard
url: https://github.com/google/briolette/tree/main/docs/design/explainers/introduction.md
transition: pull
---

# Briolette

A framework for digital value exchange

---

## What is it?

* It's not money
* It's a way to exchange value -- money, points, credits, whatever!
* It's a way to exchange value _digitally_ -- with computers, phones, or cards
* It's a way to _directly_ exchange value digitally -- online or in-person
* It's a _reliable_ way to directly exchange value digitally -- works anywhere, anytime

---

## What does that mean?

* You could withdraw money from your bank onto your phone
    * And send it to my phone directly
        - Over email, sms, wifi, bluetooth, NFC, QR code scanning, ...
    * Or pay for a purchase at a store
* Anything remaining can be deposited back with your bank from your phone or just held
  
---

## How is it not money then?

* Money is the combination of payment method and a value guarantee
* We use digital payments all the time
    * like credit cards or peer-to-peer payment mobile apps
* Most payments systems today provide their own method of exchange value (called "rails)
    - and guarantee the systems will exchange some underlying fiat value
* For instance, a merchant may be paid by a credit card or bank transfer
    - The rails connect the payer and payee
    - The value is guaranteed by the businesses involved, like payment providers or banks
* briolette provides a different approach to rails

---

## What's the approach?

- Tokens are embued with value by the system operator
    - whether it's a central bank, commercial bank, or private business
    - in most cases, they will assign a monetary value, but it could be frequent flyer points!
- Similarly, wallets are allowed to send and receive tokens, using cryptography, by the system operator
- Tokens may then be securely exchanged between users with enabled wallets
- The digital tokens are used like physical cash
    - Once transferred, the payment is complete and can be immediately spent again

---

## So how is that different?

- Many of the guarantees and goals are the same
    - Some rails operators even require trusted wallets
- The difference is largely in how authorization works
- Most payment rails require an online authorization for a payment to proceed
- Authorization of a transaction is part of the transaction process not part of the value transfer
    - Delayed authorizations, like when a merchant is offline, work but the merchant cannot access any of that value until they have settled online
- With briolette, authorization is carried with the value and does not depend on online validation

---

## Can I just cut-and-paste tokens? How could this work?
 
- Tokens themselves aren't secret and copying them doesn't help
    - For a token to have value, any transfer must be between valid wallets and signed off by the last wallet to receive it
    - Wallets rely on cryptographic keys and those shouldn't be easily copied or misused
- Your phone (or other digital wallet) should have a few specific features to help with this
    - by protecting the keys that let you send and receive money from being stolen
    - disallowing transfers of the same token to be signed off more than once (e.g., double spent or "copied")
- Even if these features get bypassed, briolette still provides a mean to detect and trace when tokens are copied
---

## Wait. Can it trace me?

- Not at all.
- Every time a token is transferred from one wallet to another, the sending wallet signs off on it
    - these sign offs are kept as a chain of transfers for each token
- For legitimate transfers, any wallet's sign off looks like any other
    - except that there may be a random, shared "group" number associated
- When a token is transferred more than once from the same wallet, its sign offs become connected (or linkable)
    - but the system still doesn't know "who" you are

---

## So how does that help?

- When a token is shared online with the system operator,
    - branches in the chain of transfers will show if a token has been copied
        - and provide the random group number along with the linkable sign offs
- This allow wallets avoid other wallets in a known "bad" group
    - and services to disallow wallets from getting new groups if they can be linked to the bad behavior

---

## Why does anyone show the tokens back to the operator?

- As tokens are transferred, the addition of wallet sign offs cause them to grow
    - At some point, they become too large to exchange and need to be swapped for a fresh token
- Private banks, or anyone handling large transfers, may wish to validate their tokens, like many do with cash today
    - The operator will provide a validation service for this   

---

## Ok, but how do wallets learn about "bad" groups?

- The system operator posts an update at a regular interval (called 'epochs')
- Wallets will either collect these updates directly or receive the updates from other wallets when transacting

---

## Why does my wallet need an update?

- In practice, it doesn't!
- However, these updates help keep the system reliable
    - If trust in a server or other wallets changes, updates keep your wallet working
- And wallets cannot perform an infinite number of transactions forever
    - They have to collect 'tickets' which allow them to transact during a time period
    - This time period is defined by the system 'epochs'

---

## This is a lot.
## So what happens if my wallet is in a "bad" group?

- Your wallet will need to go online and get new tickets
    - It may need to "prove" it isn't the misbehaving wallet
- If the misbehaving wallet was because of a security bug in wallets like yours
    - You may need to update your wallet to get back online
    - Your tokens won't be lost, but it will be an inconvenience

---

## What happens if there aren't any security updates? Am I stuck?

- It is expected that wallet providers (software and hardware) will meet certain requirements
   - If that doesn't happen, a new wallet may be needed!
- However, the system operator can still allow you to recover your tokens to the new wallet

---

## Recover? Does that mean I can get my tokens back if I lose my wallet?

- Yes!
- If the operator has configured tokens that expire
    - The operator may re-issue tokens back to the last wallet they were seen at
- In the case of a wallet provider failure, the known broken wallets can indicate the new recipient of the tokens

---

### Expiring tokens seems tricky. Will I lose money?

- Expiration only means that an online check-in needs to occur before the token can be used again
- This is a good reason to check in with the operator
    - If the operator knows the (unlinkable) last recipient of a token prior to expiration, it can swap the token
- If a token is transferred and then let expire without checking in, it's possible that it will be lost
    - Most operators will have a grace period to allow valid transactions to come in after the expiration date
- The time to recover tokens depends on both the expiration time and grace period


---

### I'd like to learn more.

- Check out our other documentation!
    - [Design Documents](https://github.com/google/briolette/tree/main/docs/design)
    - Other [explainers](https://github.com/google/briolette/tree/main/docs/design/explainers)
