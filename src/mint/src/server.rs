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

use briolette_crypto::v0;
use briolette_proto::briolette::mint::{GetTokensReply, GetTokensRequest};
use briolette_proto::briolette::token;
use briolette_proto::briolette::token::VerifyTicket;
use briolette_proto::briolette::tokenmap::token_map_client::TokenMapClient;
use briolette_proto::briolette::tokenmap::UpdateRequest;
use briolette_proto::briolette::Version;
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};

use ecdsa::RecoveryId;
use log::{error, trace, warn};
use p256::ecdsa::{signature::RandomizedSigner, Signature, SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use prost::Message;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct BrioletteMint {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    ttc_group_public_key: Vec<u8>,
    ticket_signing_keys: Vec<Vec<u8>>,
    tokenmap_uri: String,
}

impl BrioletteMint {
    pub fn new(
        mint_secret_key: Vec<u8>,
        ttc_group_public_key: Vec<u8>,
        ticket_signing_keys: Vec<Vec<u8>>,
        tokenmap_uri: String,
    ) -> Result<Self, String> {
        if mint_secret_key.len() == 0
            || ttc_group_public_key.len() == 0
            || ticket_signing_keys.len() == 0
        {
            // TODO: clean this up.
            return Err("TTC and ticket_signing_keys must not be empty.".to_string());
        }
        // Instantiate useful objects.
        let vk: VerifyingKey;
        let sk: SigningKey;
        if let Ok(maybe_sk) = SigningKey::from_bytes(mint_secret_key.as_slice()) {
            sk = maybe_sk;
            let secret_key: SecretKey = sk.clone().into();
            let pk: PublicKey = secret_key.public_key();
            vk = pk.into();
        } else {
            return Err("failed to initialize keys".to_string());
        }

        Ok(Self {
            signing_key: sk,
            verifying_key: vk,
            ttc_group_public_key,
            ticket_signing_keys,
            tokenmap_uri,
        })
    }

    // We always provide a non-async implementation for cleaner testing.
    // It also allows migration to different wrapping frameworks.
    pub async fn get_tokens_impl(
        &self,
        request: &GetTokensRequest,
    ) -> Result<GetTokensReply, BrioletteError> {
        trace!("get_tokens: request = {:?}", &request);
        // 1. Validate the version
        if request.version != Version::Current as i32 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }

        // 2. Check for the arguments
        if request.count == 0 || request.ticket.is_none() || request.amount.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        let amount = request.amount.clone().unwrap();
        // Optionally, enforce maximum and minimum token amounts and count.
        if amount.code != token::AmountType::TestToken as i32 {
            warn!("requested currency type unsupported: {}", amount.code);
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidAmountType.into(),
            });
        }

        // 3. Verify the ticket
        let signed_ticket = request.ticket.clone().unwrap();
        if let Err(code) = signed_ticket.verify(&self.ticket_signing_keys, None) {
            return Err(BrioletteError { code: code.into() });
        }

        // Ensure the credential is for a supported TTC group
        let recipient = signed_ticket.ticket.clone().unwrap().credential;
        if v0::credential_in_group(&recipient, &self.ttc_group_public_key) == false {
            trace!("signed ticket credential not in a known TTC!");
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidTicketGroup.into(),
            });
        }
        // 4. Ticket is valid, so let's make some tokens!
        let mut reply = GetTokensReply::default();
        for _i in 0..request.count {
            let desc = Some(token::Descriptor {
                version: token::Version::V0.into(),
                value: Some(amount.clone()),
            });
            let base = token::Transfer {
                recipient: Some(signed_ticket.clone()),
                tags: request.tags.clone(),
                // We bind the descriptor to the first transfer here.
                previous_signature: Sha256::digest(desc.clone().unwrap().encode_to_vec()).to_vec(),
            };
            // TODO: Move to proto as a trait
            // Sign the transfer
            let transfer_serialized = base.encode_to_vec();
            let sig: Signature = self
                .signing_key
                .sign_with_rng(&mut OsRng, transfer_serialized.as_slice());
            let mut signature = sig.to_vec();
            if let Ok(rec_id) = RecoveryId::trial_recovery_from_msg(
                &self.verifying_key,
                transfer_serialized.as_slice(),
                &sig,
            ) {
                signature.push(rec_id.to_byte());
            } else {
                trace!("Could not find recovery id");
                return Err(BrioletteError {
                    code: BrioletteErrorCode::FailedToSignTokenTransfer.into(),
                });
            }
            let history = token::History {
                transfer: Some(base),
                signature: signature.clone(),
            };
            let token = token::Token {
                descriptor: desc,
                base: Some(history),
                history: vec![],
            };
            // Write the token to the tokenmap.
            // TODO: Move the client into its own thread at setup and thunk over tokens.
            if self.tokenmap_uri.len() != 0 {
                if update_tokenmap(token.clone(), &self.tokenmap_uri).await {
                    // Don't release tokens that aren't tracked.
                    reply.tokens.push(token);
                } else {
                    warn!("Token not returned due to tokenmap failure.");
                }
            } else {
                warn!("Tokens not being stored centrally!");
            }
        }
        return Ok(reply);
    }
}

async fn update_tokenmap(token: token::Token, uri: &String) -> bool {
    if let Ok(mut client) = TokenMapClient::connect(uri.clone()).await {
        trace!("Connected to tokenmap!");
        let request = UpdateRequest {
            id: token.clone().base.unwrap().signature,
            token: Some(token.clone()),
        };
        if let Ok(response) = client.update(request).await {
            // This shouldn't happen, but this is a reminder that it could.
            let msg = response.into_inner();
            if msg.created == false {
                error!("mint created a known token!");
                return false;
            }
            trace!("Updated tokenmap!");
            return true;
        }
    }
    return false;
}
