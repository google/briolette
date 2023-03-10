// Copyright 2023 The Briolette Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

tonic::include_proto!("briolette.token");
use crate::vec_utils;
use chrono::Utc;
use ecdsa::RecoveryId;
//use ettecrypto::v0;
use crate::briolette::ErrorCode as BrioletteErrorCode;
use briolette_crypto::v0;
use log::*;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use prost::Message;
use sha2::{Digest, Sha256};
use std::ops::Add;

// TODO: make configurable
const EPOCH_SECONDS: u32 = 86400;

pub trait TokenVerify {
    //  Returns true if the Token is valid. If trusted_mints are supplied, the base will be
    //  verified as well. If trusted_clerks are supplied, then the tickets will be verified as
    //  well.
    fn verify(
        &self,
        group_public_key: &Vec<u8>,
        trusted_mints: &Vec<Vec<u8>>,
        trusted_clerks: &Vec<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode>;
}

impl TokenVerify for Token {
    fn verify(
        &self,
        group_public_key: &Vec<u8>,
        trusted_mints: &Vec<Vec<u8>>,
        trusted_clerks: &Vec<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode> {
        if self.base.is_none() || self.descriptor.is_none() {
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        // 1. Verify the base
        self.base.as_ref().unwrap().verify_base(
            self.descriptor.as_ref().unwrap(),
            trusted_mints,
            trusted_clerks,
        )?;

        // 2, Verify each history entry
        let mut last_signature = &self.base.as_ref().unwrap().signature;
        let mut bound_credential = &self
            .base
            .as_ref()
            .unwrap()
            .transfer
            .as_ref()
            .unwrap()
            .recipient
            .as_ref()
            .unwrap()
            .ticket
            .as_ref()
            .unwrap()
            .credential;
        for history in self.history.iter() {
            history.verify_history(
                bound_credential,
                last_signature,
                group_public_key,
                trusted_clerks,
            )?;
            last_signature = &history.signature;
            bound_credential = &history
                .transfer
                .as_ref()
                .unwrap()
                .recipient
                .as_ref()
                .unwrap()
                .ticket
                .as_ref()
                .unwrap()
                .credential;
        }
        // 3. Enjoy a valid token.
        return Ok(true);
    }
}
pub trait HistoryVerify {
    fn verify_history(
        &self,
        bound_credential: &Vec<u8>,
        previous_signature: &Vec<u8>,
        group_public_key: &Vec<u8>,
        allowed_ticket_keys: &Vec<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode>;
    fn verify_base(
        &self,
        descriptor: &Descriptor,
        allowed_mint_keys: &Vec<Vec<u8>>,
        allowed_ticket_keys: &Vec<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode>;
}

impl HistoryVerify for History {
    fn verify_history(
        &self,
        bound_credential: &Vec<u8>,
        previous_signature: &Vec<u8>,
        group_public_key: &Vec<u8>,
        allowed_ticket_keys: &Vec<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode> {
        if self.transfer.is_none() || self.transfer.as_ref().unwrap().recipient.is_none() {
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        self.transfer
            .as_ref()
            .unwrap()
            .recipient
            .as_ref()
            .unwrap()
            .verify(&allowed_ticket_keys, None)?;

        let mut transfer = self.transfer.clone().unwrap();
        transfer.previous_signature = previous_signature.clone();
        let transfer_serialized = transfer.encode_to_vec();

        // Re-insert the bound credential into the signature
        let mut signature = self.signature.clone();
        v0::inflate_signature(bound_credential, &mut signature);
        let verified = v0::verify(
            group_public_key,
            &Some(previous_signature.clone()),
            &Some(bound_credential.clone()),
            &signature,
            &transfer_serialized,
        );
        if verified {
            return Ok(true);
        }
        return Err(BrioletteErrorCode::InvalidHistorySignature);
    }

    fn verify_base(
        &self,
        descriptor: &Descriptor,
        allowed_mint_keys: &Vec<Vec<u8>>,
        allowed_ticket_keys: &Vec<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode> {
        if self.transfer.is_none() || self.transfer.as_ref().unwrap().recipient.is_none() {
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        // Start with the ticket
        self.transfer
            .as_ref()
            .unwrap()
            .recipient
            .as_ref()
            .unwrap()
            .verify(&allowed_ticket_keys, None)?;
        let mut sig: Vec<u8> = self.signature.clone();
        if sig.len() == 0 {
            debug!("base missing signature");
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        let rec_id = RecoveryId::try_from(sig.pop().unwrap());
        if rec_id.is_err() {
            debug!("could not recover public key");
            return Err(BrioletteErrorCode::UnrecoverablePublicKey);
        }
        let mut base = self.transfer.clone().unwrap();
        // For this one, we want the digest of the descriptor..
        base.previous_signature = Sha256::digest(descriptor.encode_to_vec()).to_vec();
        let serialized = base.encode_to_vec();
        if let Ok(signature) = Signature::try_from(sig.as_slice()) {
            // Recovery the public key
            let found_vk: VerifyingKey;
            let found_vk_bytes: Vec<u8>;
            if let Ok(vk) =
                VerifyingKey::recover_from_msg(serialized.as_slice(), &signature, rec_id.unwrap())
            {
                found_vk = vk;
                found_vk_bytes = vk.to_public_key_der().unwrap().as_bytes().to_vec();
            } else {
                debug!("could not recover public key");
                return Err(BrioletteErrorCode::UnrecoverablePublicKey);
            }
            // See if it is known
            let mint_vk: VerifyingKey;
            if let Some(_tsk) = allowed_mint_keys
                .iter()
                .find(|&key| vec_utils::vec_equal(key, &found_vk_bytes))
            {
                mint_vk = found_vk;
            } else {
                trace!("no known public key found for ticket");
                return Err(BrioletteErrorCode::UnknownMintPublicKey);
            }
            if let Err(e) = mint_vk.verify(serialized.as_slice(), &signature) {
                trace!("ticket signature did not verify: {:?}", e);
                return Err(BrioletteErrorCode::InvalidBaseSignature);
            }
            return Ok(true);
        }
        Err(BrioletteErrorCode::UnparseableBaseSignature)
    }
}

pub trait TokenTransfer {
    fn transfer(
        &mut self,
        destination: &SignedTicket,
        credential_secret: Vec<u8>,
    ) -> Result<bool, BrioletteErrorCode>;
    // TODO: Pull base signing out of Mint
    // fn base(&mut self, ...)
}

impl TokenTransfer for Token {
    fn transfer(
        &mut self,
        destination: &SignedTicket,
        credential_secret: Vec<u8>,
    ) -> Result<bool, BrioletteErrorCode> {
        // Grab the last signature to use as the basename and in the tx block.
        let last_sig;
        let committed_credential;
        if let Some(last_tx) = self.history.last() {
            last_sig = last_tx.signature.clone();
            committed_credential = last_tx
                .transfer
                .as_ref()
                .unwrap()
                .recipient
                .as_ref()
                .unwrap()
                .ticket
                .as_ref()
                .unwrap()
                .credential
                .clone();
        } else {
            last_sig = self
                .base
                .as_ref()
                .expect("transfer cannot be called with no base")
                .signature
                .clone();
            committed_credential = self
                .base
                .as_ref()
                .unwrap()
                .transfer
                .as_ref()
                .unwrap()
                .recipient
                .as_ref()
                .unwrap()
                .ticket
                .as_ref()
                .unwrap()
                .credential
                .clone();
        }
        let mut transfer = Transfer {
            recipient: Some(destination.clone()),
            tags: vec![],
            previous_signature: last_sig.clone(),
        };
        let serialized_transfer = transfer.encode_to_vec();
        let basename = Some(last_sig);
        let mut signature = vec![];
        if v0::sign(
            &serialized_transfer,
            &committed_credential,
            &credential_secret,
            &basename,
            false, // require the committed credential!
            &mut signature,
        ) == false
        {
            return Err(BrioletteErrorCode::FailedToSignTokenTransfer);
        }
        // Don't duplicate the storage here.
        transfer.previous_signature.clear();
        // Remove the duplicated credential from the Token when serialized
        // This saves 260 bytes per transfer. At present, history is 515 bytes.
        v0::deflate_signature(&mut signature);
        let history = History {
            transfer: Some(transfer),
            signature,
        };
        self.history.push(history);
        return Ok(true);
    }
}

pub trait TicketExpiry {
    fn expires_on(&self) -> u64;
}

impl TicketExpiry for SignedTicket {
    fn expires_on(&self) -> u64 {
        let ticket_tags = self.ticket.clone().unwrap().tags.unwrap();
        ticket_tags.created_on + ((ticket_tags.lifetime * EPOCH_SECONDS) as u64)
    }
}

pub trait VerifyTicket {
    // TODO: Move to common error codes.
    fn verify(
        &self,
        allowed_signing_keys: &Vec<Vec<u8>>,
        credential: Option<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode>;
}

impl VerifyTicket for SignedTicket {
    fn verify(
        &self,
        allowed_signing_keys: &Vec<Vec<u8>>,
        credential: Option<Vec<u8>>,
    ) -> Result<bool, BrioletteErrorCode> {
        let serialized: Vec<u8>;
        if let Some(mut ticket) = self.ticket.clone() {
            if credential.is_some() && ticket.credential.len() == 0 {
                ticket.credential = credential.clone().unwrap();
            }
            serialized = ticket.encode_to_vec();
        } else {
            debug!("ticket missing");
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        // Verify the signature -- fallthrough is valid.
        let mut sig: Vec<u8> = self.signature.clone();
        if sig.len() == 0 {
            debug!("ticket missing signature");
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        let rec_id = RecoveryId::try_from(sig.pop().unwrap());
        if rec_id.is_err() {
            debug!("could not recover public key");
            return Err(BrioletteErrorCode::UnrecoverablePublicKey);
        }
        if let Ok(signature) = Signature::try_from(sig.as_slice()) {
            // Recovery the public key
            let found_vk: VerifyingKey;
            let found_vk_bytes: Vec<u8>;
            if let Ok(vk) =
                VerifyingKey::recover_from_msg(serialized.as_slice(), &signature, rec_id.unwrap())
            {
                found_vk = vk;
                found_vk_bytes = vk.to_public_key_der().unwrap().as_bytes().to_vec();
            } else {
                debug!("could not recover public key");
                return Err(BrioletteErrorCode::UnrecoverablePublicKey);
            }
            // See if it is known
            let ticket_vk: VerifyingKey;
            if let Some(_tsk) = allowed_signing_keys
                .iter()
                .find(|&key| vec_utils::vec_equal(key, &found_vk_bytes))
            {
                ticket_vk = found_vk;
            } else {
                trace!("no known public key found for ticket");
                return Err(BrioletteErrorCode::UnknownTicketPublicKey);
            }
            if let Err(e) = ticket_vk.verify(serialized.as_slice(), &signature) {
                trace!("ticket signature did not verify: {:?}", e);
                return Err(BrioletteErrorCode::InvalidTicketSignature);
            }

            // Now we need to check any relevant tags
            let now = Utc::now().timestamp() as u64;
            let tags = self.ticket.clone().unwrap().tags.clone().unwrap();
            // TODO: Ensure valid group_number range.
            if tags.created_on >= now {
                trace!("ticket created in the future: {}", tags.created_on);
                return Err(BrioletteErrorCode::InvalidTicketCreatedOn);
            }
            if self.expires_on() < now {
                trace!("ticket expired");
                return Err(BrioletteErrorCode::TicketExpired);
            }

            return Ok(true);
        }
        Err(BrioletteErrorCode::UnparseableTicketSignature)
    }
}

impl Add for Amount {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        // TODO clean up
        assert_eq!(self.code, other.code);
        Self {
            whole: self.whole + other.whole,
            fractional: self.fractional + other.fractional,
            code: self.code,
        }
    }
}
