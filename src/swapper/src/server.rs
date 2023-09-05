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

use briolette_proto::briolette::swapper::{
    GetDestinationReply, GetDestinationRequest, SwapTokensReply, SwapTokensRequest,
};
use briolette_proto::briolette::token::{SignedTicket, Token};
use briolette_proto::briolette::Version;
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};
use briolette_wallet::{Wallet, WalletData};
use log::*;
use prost::Message;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct BrioletteSwapper {
    ticket: SignedTicket,
    wallet: Arc<RwLock<WalletData>>,
}
impl BrioletteSwapper {
    pub async fn new(
        registrar_uri: String,
        clerk_uri: String,
        mint_uri: String,
        validate_uri: String,
    ) -> Result<Self, BrioletteErrorCode> {
        trace!("initializing wallet");
        let mut wd = WalletData::new(registrar_uri, clerk_uri, mint_uri, validate_uri);
        assert!(wd.initialize_keys(b"swapper-wallet-001"));
        assert!(wd.initialize_credential().await);
        assert!(wd.synchronize().await);
        assert!(wd.get_tickets(2).await);
        // "Withdraw" from the mint
        // TODO: Make this dynamic, etc.
        assert!(wd.withdraw(25).await);

        assert!(wd.tickets.len() > 0);
        Ok(Self {
            ticket: wd.tickets[0].clone().into(),
            wallet: Arc::new(RwLock::new(wd)),
        })
    }

    pub async fn get_destination_impl(
        &self,
        request: &GetDestinationRequest,
    ) -> Result<GetDestinationReply, BrioletteError> {
        trace!("validate_tokens: request = {:?}", &request);
        let mut reply = GetDestinationReply::default();
        reply.swap_ticket = Some(self.ticket.clone());
        return Ok(reply);
    }

    pub async fn swap_tokens_impl(
        &self,
        request: &SwapTokensRequest,
    ) -> Result<SwapTokensReply, BrioletteError> {
        trace!("validate_tokens: request = {:?}", &request);
        // 1. Swapper the version
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
        // 3. Verify each token against the validation server
        let mut reply = SwapTokensReply::default();
        // Separate out the locked data since we only need the validate call.
        // TODO: Refactor the wallet data and services to avoid this.
        let wallet_shell = self.wallet.read().unwrap().clone();
        if wallet_shell.validate_tokens(&request.tokens.clone()).await {
            for token in request.tokens.iter() {
                let sender;
                let destination;
                if token.history.len() > 1 {
                    sender = token
                        .history
                        .iter()
                        .last()
                        .unwrap()
                        .transfer
                        .as_ref()
                        .unwrap()
                        .recipient
                        .as_ref()
                        .unwrap();
                } else {
                    sender = token
                        .base
                        .as_ref()
                        .unwrap()
                        .transfer
                        .as_ref()
                        .unwrap()
                        .recipient
                        .as_ref()
                        .unwrap();
                }
                destination = token
                    .history
                    .iter()
                    .last()
                    .unwrap()
                    .transfer
                    .as_ref()
                    .unwrap()
                    .recipient
                    .as_ref()
                    .unwrap();
                // 4. For each token transferred to the swapper, transfer a token to the sender.
                if destination.ticket.as_ref().unwrap().credential
                    == self.ticket.ticket.as_ref().unwrap().credential
                {
                    // TODO: Handle being out of tokens and different values, whole and fractional
                    if self.wallet.write().unwrap().transfer(
                        token
                            .descriptor
                            .as_ref()
                            .unwrap()
                            .value
                            .clone()
                            .unwrap()
                            .whole as u32,
                        sender.clone().encode_to_vec(),
                    ) == true
                    {
                        let pending = self.wallet.write().unwrap().pending_tokens.pop().unwrap();
                        reply
                            .tokens
                            .push(Token::decode(pending.as_slice()).unwrap());
                    }
                }
            }
        }
        return Ok(reply);
    }
}
