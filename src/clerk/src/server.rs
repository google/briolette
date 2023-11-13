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

use briolette_proto::briolette::clerk::{
    AddEpochReply, EpochReply, EpochRequest, EpochUpdate, EpochVerify, GetTicketsReply,
    GetTicketsRequest,
};
use briolette_proto::briolette::token::{SignedTicket, Ticket, TicketData};
use briolette_proto::briolette::tokenmap::token_map_client::TokenMapClient;
use briolette_proto::briolette::tokenmap::{LinkableSignature, StoreTicketsRequest};
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};

use briolette_proto::briolette::Version;

use bytes::Bytes;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

use briolette_crypto::v0;
use ecdsa::RecoveryId;
use log::trace;
use p256::ecdsa::{signature::RandomizedSigner, Signature, SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use prost::Message;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct BrioletteClerk {
    ticket_signing_key: SigningKey,
    epoch_verifying_key: VerifyingKey,
    epoch_update: Arc<RwLock<Option<EpochUpdate>>>, // Interior Mutability
    pub tokenmap_uri: String,
}
// Initially, this will be stored and loaded to persist state.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BrioletteClerkSerializable {
    ticket_signing_key: Vec<u8>,    // Private key
    epoch_verifying_key: PublicKey, // Public key
    epoch_update: Vec<u8>,          // serialized update
    tokenmap_uri: String,
}

#[derive(Debug, Clone, Default)]
pub struct ClerkError {}
impl fmt::Display for ClerkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClerkError placeholder")
    }
}
impl std::error::Error for ClerkError {}

impl BrioletteClerk {
    pub fn load(data_file: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        // Open the file in read-only mode with buffer.
        let maybe_clerk = std::fs::read(data_file);
        if let Ok(clerk) = maybe_clerk {
            match serde_json::from_slice::<BrioletteClerkSerializable>(&clerk) {
                Ok(x) => {
                    let mut eu: Option<EpochUpdate> = None;
                    if x.epoch_update.len() > 0 {
                        if let Ok(maybe_eu) = EpochUpdate::decode(Bytes::from(x.epoch_update)) {
                            eu = Some(maybe_eu);
                        }
                    }
                    let vk: VerifyingKey = x.epoch_verifying_key.into();
                    Ok(BrioletteClerk {
                        ticket_signing_key: SigningKey::from_bytes(
                            x.ticket_signing_key.as_slice(),
                        )?,
                        epoch_verifying_key: vk,
                        epoch_update: Arc::new(RwLock::new(eu)),
                        tokenmap_uri: x.tokenmap_uri,
                    })
                }
                Err(e) => Err(Box::new(e)),
            }
        } else {
            Err(Box::new(ClerkError::default()))
        }
    }

    pub fn write_key(&self, data_file: &Path) -> Result<bool, Box<dyn std::error::Error>> {
        let sk: SecretKey = self.ticket_signing_key.clone().into();
        std::fs::write(&data_file, sk.to_pkcs8_der().unwrap().as_bytes())?;
        Ok(true)
    }

    pub fn write_public_key(&self, data_file: &Path) -> Result<bool, Box<dyn std::error::Error>> {
        let sk: SecretKey = self.ticket_signing_key.clone().into();
        let pk: PublicKey = sk.public_key();
        std::fs::write(&data_file, pk.to_public_key_der().unwrap().as_bytes())?;
        Ok(true)
    }

    pub fn store(&self, data_file: &Path) -> Result<bool, Box<dyn std::error::Error>> {
        let es = BrioletteClerkSerializable {
            ticket_signing_key: self.ticket_signing_key.to_bytes().as_slice().to_vec(),
            epoch_verifying_key: self.epoch_verifying_key.clone().into(),
            epoch_update: self
                .epoch_update
                .read()
                .unwrap()
                .clone()
                .ok_or(EpochUpdate::default())
                .unwrap_or(EpochUpdate::default())
                .encode_to_vec(),
            tokenmap_uri: self.tokenmap_uri.clone(),
        };
        std::fs::write(&data_file, serde_json::to_vec(&es).unwrap())?;
        Ok(true)
    }

    // Generates new keys for ticket signing.
    pub fn new(os_rng: &mut OsRng, epoch_public_key: &VerifyingKey, tokenmap_uri: String) -> Self {
        Self {
            ticket_signing_key: SigningKey::random(os_rng), // TODO(wad) make seed/mock able.
            epoch_verifying_key: epoch_public_key.clone(),
            epoch_update: Arc::new(RwLock::new(None)),
            tokenmap_uri,
        }
    }

    // We always provide a non-async implementation for cleaner testing.
    // It also allows migration to different wrapping frameworks.
    pub async fn get_tickets_impl(
        &self,
        request: &GetTicketsRequest,
    ) -> Result<GetTicketsReply, BrioletteError> {
        trace!("get_tickets: request = {:?}", &request);
        // 1. Validate the version
        if request.version != Version::Current as i32 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }

        // 2. Check for the ticket requests
        if request.requests.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }

        // Grab a thread-local copy of epoch update
        let eu = self.epoch_update.read().unwrap().clone();
        if eu.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidServerState.into(),
            });
        }
        // Check if the NAC and TTC group public keys are in our
        // trusted stack (in EpochUpdate::ExtendedEpochData.
        let eed = eu.clone().unwrap().extended_data.unwrap();
        if eed.ttc_group_public_keys.contains(&request.ttc_public_key) == false {
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTokenTransferGroupPublicKey.into(),
            });
        }
        // TODO Add trusted NAC checking
        // let nac_ok = self.trusted_nac_gpks.contains(&request.nac_public_key);
        // TODO Add error that redirects the caller back to their registrar to get
        //      a new credential after signing with a revoked pseudonym. The other
        //      option is to do that here as well.
        // TODO Add pseudonym extraction and storage per-epoch to limit ticket
        //      requests

        let ed = eu.clone().unwrap().data.unwrap();

        // If they have the wrong epoch, the basename will be incorrect.
        if request.known_epoch < ed.epoch {
            return Err(BrioletteError {
                code: BrioletteErrorCode::EpochUpdateRequired.into(),
            });
        }

        // Serialize TicketRequests and verify the supplied NAC signature.
        let tr_msg = request.requests.clone().unwrap().encode_to_vec();
        let basename = Some(ed.epoch.to_le_bytes().to_vec());
        if v0::verify(
            &request.nac_public_key,
            &basename,
            &None,
            &request.nac_signature,
            &tr_msg,
        ) == false
        {
            trace!("NAC signature for the ticket request did not verify.");
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidSignature.into(),
            });
        }
        let mut reply = GetTicketsReply::default();
        // Spray the secret keys all over memory! =)
        let sk: SecretKey = self.ticket_signing_key.clone().into();
        let pk: PublicKey = sk.public_key();
        reply.signing_key = pk.to_public_key_der().unwrap().as_bytes().to_vec();

        // Walk each credential and
        // A. Check if it is in the TTC GPK
        // B. Create and sign a ticket!
        for ticket_req in &request.requests.clone().unwrap().request {
            let ticket = Ticket {
                credential: ticket_req.credential.clone(),
                tags: Some(TicketData {
                    group_number: ticket_req.group_number,
                    lifetime: 7, // TODO: make dynamic
                    created_on: ed.epoch,
                }),
            };
            // Before signing, let's confirm the credential matches the TTC.
            if v0::credential_in_group(&ticket.credential, &request.ttc_public_key) == false {
                trace!("NAC signature for the ticket request did not verify.");
                return Err(BrioletteError {
                    code: BrioletteErrorCode::CredentialInvalidForGroup.into(),
                });
            }
            // Sign with the ticket server key.
            let serialized_ticket = ticket.encode_to_vec();
            // Fails? sign_recoverable(serialized_ticket.as_slice())
            let mut signature: Vec<u8>;
            let sig: Signature = self
                .ticket_signing_key
                .sign_with_rng(&mut OsRng, serialized_ticket.as_slice());
            signature = sig.to_vec();
            if let Ok(rec_id) =
                RecoveryId::trial_recovery_from_msg(&pk.into(), serialized_ticket.as_slice(), &sig)
            {
                signature.push(rec_id.to_byte());
            } else {
                trace!("Could not find recovery id");
                return Err(BrioletteError {
                    code: BrioletteErrorCode::FailedToSignTicket.into(),
                });
            }
            let signed_ticket = SignedTicket {
                ticket: Some(ticket),
                signature: signature,
            };
            reply.tickets.push(signed_ticket);
        }
        // TODO: Rely on the ticket_store/token_map to track issued tickets to map NAC<>group<>expiration and credential<>nac
        // TODO: optionally track ticket grouping
        let nac_sig = LinkableSignature {
            signature: request.nac_signature.clone(),
            basename: basename.clone().unwrap(),
            group_public_key: request.nac_public_key.clone(),
        };
        if update_ticket_store(reply.tickets.clone(), nac_sig, &self.tokenmap_uri).await == false {
            // Do not issue tickets if we can't store them.
            // The system would operate fine, but we would be unable to relink to the NAC on
            // abuse.
            return Err(BrioletteError {
                code: BrioletteErrorCode::TokenMapFailure.into(),
            });
        }

        // 4. Return the new tickets.
        return Ok(reply);
    }
    // We always provide a non-async implementation for cleaner testing.
    // It also allows migration to different wrapping frameworks.
    pub fn add_epoch_impl(&self, request: &EpochUpdate) -> Result<AddEpochReply, BrioletteError> {
        // Validate request
        if request.version != Version::Current as i32 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }

        if !request.data.is_some()
            || !request.extended_data.is_some()
            || request.epoch_signature.len() == 0
            || request.signing_key.len() == 0
        {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        let epoch_pk: PublicKey = self.epoch_verifying_key.clone().into();
        let epoch_pk_der: Vec<u8> = epoch_pk.to_public_key_der().unwrap().as_bytes().to_vec();
        request.verify(&epoch_pk_der)?;
        if true {
            // Small block for the lock
            // Update internal state.
            trace!("Grabbing EU write lock...");
            let mut eu = self.epoch_update.write().unwrap();
            trace!("Got it!");
            *eu = Some(request.clone());
            trace!("Releasing write lock...");
        }
        // Store our latest state
        // TODO: PARAMETERIZE
        trace!("Writing to disk...");
        if let Err(_e) = self.store(&Path::new("data/clerk/clerk.state")) {
            return Err(BrioletteError {
                code: BrioletteErrorCode::ServerDiskError.into(),
            });
        }
        let reply = AddEpochReply::default();
        trace!("Sending the reply....");
        Ok(reply)
    }
    pub fn get_epoch_impl(&self, request: &EpochRequest) -> Result<EpochReply, BrioletteError> {
        trace!("get_tickets: request = {:?}", &request);
        // 1. Validate the version
        if request.version != Version::Current as i32 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }

        // Send the update only if the known_epoch is older than the current epoch.
        let mut reply = EpochReply::default();
        if let Some(eu) = self.epoch_update.read().unwrap().clone() {
            let euc = eu.clone();
            let data = euc.data.unwrap();
            if request.known_epoch < data.epoch {
                reply.update = Some(eu);
            }
        } else {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidServerState.into(),
            });
        }

        return Ok(reply);
    }
}

async fn update_ticket_store(
    signed_tickets: Vec<SignedTicket>,
    nac: LinkableSignature,
    tokenmap_uri: &String,
) -> bool {
    if let Ok(mut client) = TokenMapClient::connect(tokenmap_uri.clone()).await {
        eprintln!("Connected to tokenmap!");
        let request = StoreTicketsRequest {
            tickets: signed_tickets,
            nac: Some(nac),
        };
        if let Ok(_) = client.store_tickets(request).await {
            eprintln!("Updated ticket store!");
            return true;
        }
        eprintln!("store_tickets call failed!");
    }
    return false;
}
