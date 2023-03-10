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
use briolette_proto::briolette::clerk::{EpochRequest, EpochUpdate};
use briolette_proto::briolette::token;
use briolette_proto::briolette::token::TokenVerify;
use briolette_proto::briolette::tokenmap::token_map_client::TokenMapClient;
use briolette_proto::briolette::tokenmap::UpdateRequest;
use briolette_proto::briolette::validate::{ValidateTokensReply, ValidateTokensRequest};
use briolette_proto::briolette::Version;
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};
use log::*;

#[derive(Debug, Clone)]
pub struct BrioletteValidate {
    epoch_update: EpochUpdate,
    clerk_uri: String,
    tokenmap_uri: String,
    epoch_pk: Vec<u8>,
}
impl BrioletteValidate {
    pub async fn new(
        clerk_uri: String,
        tokenmap_uri: String,
        epoch_pk: Vec<u8>,
    ) -> Result<Self, BrioletteErrorCode> {
        if clerk_uri.len() == 0 || tokenmap_uri.len() == 0 || epoch_pk.len() == 0 {
            return Err(BrioletteErrorCode::InvalidMissingFields);
        }
        let eu = get_epoch_update(&clerk_uri).await?;
        trace!("collected epoch update from clerk");
        Ok(Self {
            epoch_update: eu,
            clerk_uri,
            tokenmap_uri,
            epoch_pk,
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
        for token in request.tokens.iter() {
            let extended_data = self.epoch_update.extended_data.as_ref().unwrap();
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
            if check_tokenmap(token.clone(), &self.tokenmap_uri).await == false {
                // TODO: add some metrics
                error!("bad token detected");
                reply.ok.push(false);
            } else {
                reply.ok.push(true);
            }
        }
        return Ok(reply);
    }
}

async fn get_epoch_update(clerk_uri: &String) -> Result<EpochUpdate, BrioletteErrorCode> {
    if let Ok(mut client) = ClerkClient::connect(clerk_uri.clone()).await {
        let epoch_request = tonic::Request::new(EpochRequest::default());
        if let Ok(response) = client.get_epoch(epoch_request).await {
            let msg = response.into_inner();
            if let Some(update) = msg.update {
                return Ok(update);
            }
        }
    }
    return Err(BrioletteErrorCode::ClerkFetchFailure);
}

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
    error!("failed to connected to the tokenmap");
    return false;
}
