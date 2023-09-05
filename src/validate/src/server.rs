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

use briolette_proto::briolette::clerk::clerk_client::ClerkClient;
use briolette_proto::briolette::clerk::{EpochRequest, EpochUpdate, EpochVerify};
use briolette_proto::briolette::token;
use briolette_proto::briolette::token::TokenVerify;
use briolette_proto::briolette::tokenmap::token_map_client::TokenMapClient;
use briolette_proto::briolette::tokenmap::UpdateRequest;
use briolette_proto::briolette::validate::{ValidateTokensReply, ValidateTokensRequest};
use briolette_proto::briolette::Version;
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};
use briolette_proto::briolette::{ServiceMapInterface, ServiceName};

use log::*;
use std::sync::RwLock;

#[derive(Debug)]
pub struct BrioletteValidate {
    tokenmap_uri: String,
    epoch_update: RwLock<EpochUpdate>,
}
impl BrioletteValidate {
    pub async fn new(epoch_update: &EpochUpdate) -> Result<Self, BrioletteErrorCode> {
        // TODO -- move the service mtch to proto lib
        let extended_data;
        if let Some(ed) = &epoch_update.extended_data {
            extended_data = ed.clone();
        } else {
            error!("EpochUpdate does not contain the required extended data field!");
            return Err(BrioletteErrorCode::InvalidMissingFields.into());
        }
        let tokenmap_uri = extended_data.service_map.get(ServiceName::Tokenmap);
        if tokenmap_uri.is_empty() {
            error!("EpochUpdate does not contain the tokenmap URI!");
            error!("EpochUpdate: {:?}", epoch_update);
            return Err(BrioletteErrorCode::InvalidMissingFields.into());
        }
        Ok(Self {
            tokenmap_uri: tokenmap_uri[0].clone(),
            epoch_update: RwLock::new(epoch_update.clone()),
        })
    }

    pub async fn validate_tokens_impl(
        &self,
        request: &ValidateTokensRequest,
    ) -> Result<ValidateTokensReply, BrioletteError> {
        trace!("validate_tokens: request = {:?}", &request);
        // 1. Validate the version
        if request.version != Version::Current as i32 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }

        // 2. Check for the arguments
        if request.tokens.len() == 0 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        // 3. Verify each token
        // Grab the reader lock on the EpochUpdate, but clone the ED so we don't need to keep it.
        // It is a precondition that the stored EpochUpdate has extended data.
        let extended_data = self
            .epoch_update
            .read()
            .unwrap()
            .extended_data
            .clone()
            .unwrap();
        for token in request.tokens.iter() {
            token.verify(
                &extended_data.ttc_group_public_keys[0],
                &extended_data.mint_signing_keys,
                &extended_data.ticket_signing_keys,
            )?;
        }
        // 4. Check these cryptographically valid tokens against the tokenmap
        // TODO: make this more sensible
        let mut reply = ValidateTokensReply::default();
        for token in request.tokens.iter() {
            if Self::check_tokenmap(token.clone(), &self.tokenmap_uri).await == false {
                // TODO: add some metrics
                error!("bad token detected");
                reply.ok.push(false);
            } else {
                reply.ok.push(true);
            }
        }
        return Ok(reply);
    }

    pub async fn fetch_epoch_update(
        clerk_uri: &String,
        epoch_pk: &Vec<u8>,
    ) -> Result<EpochUpdate, BrioletteErrorCode> {
        if let Ok(mut client) = ClerkClient::connect(clerk_uri.clone()).await {
            let epoch_request = tonic::Request::new(EpochRequest::default());
            if let Ok(response) = client.get_epoch(epoch_request).await {
                let msg = response.into_inner();
                if let Some(update) = msg.update {
                    if let Ok(true) = update.verify(epoch_pk) {
                        trace!("EpochUpdate fetched and verified.");
                        return Ok(update);
                    }
                    info!("EpochUpdate failed to verify.");
                }
            }
        }
        return Err(BrioletteErrorCode::ClerkFetchFailure);
    }

    // TODO(redpig) move this onto a Token trait
    async fn check_tokenmap(token: token::Token, uri: &String) -> bool {
        if let Ok(mut client) = TokenMapClient::connect(uri.clone()).await {
            trace!("Connected to tokenmap!");
            let request = UpdateRequest {
                id: token.clone().base.unwrap().signature,
                token: Some(token.clone()),
            };
            if let Ok(response) = client.update(request).await {
                // This shouldn't happen, but this is a reminder that it could.
                let msg = response.into_inner();
                return msg.abuse_detected == false;
            }
        }
        error!("failed to connected to the tokenmap: {}", uri.clone());
        return false;
    }
}
