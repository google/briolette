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

use briolette_proto::briolette::receiver::*;
use briolette_proto::briolette::token;
use briolette_proto::briolette::Version;
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};
use briolette_wallet::{Wallet, WalletData};
use log::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::{task, time};

#[derive(Debug, Clone, PartialEq)]
enum TransactionState {
    Gossip(Transaction),
    Transact(Transaction),
    Transfer(Transaction),
    Complete(Transaction),
}

impl TransactionState {
    pub fn complete(&self) -> bool {
        match self {
            TransactionState::Complete(_) => true,
            _ => false,
        }
    }
    pub fn name(&self) -> String {
        match self {
            TransactionState::Gossip(_) => "gossip",
            TransactionState::Transact(_) => "transact",
            TransactionState::Transfer(_) => "transfer",
            TransactionState::Complete(_) => "complete",
        }
        .to_string()
    }
    pub fn inner(&self) -> Transaction {
        match self {
            TransactionState::Gossip(data) => data.clone(),
            TransactionState::Transact(data) => data.clone(),
            TransactionState::Transfer(data) => data.clone(),
            TransactionState::Complete(data) => data.clone(),
        }
    }
}

impl From<TransactionState> for Transaction {
    fn from(item: TransactionState) -> Transaction {
        item.inner()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    total: f32,
    amount: token::Amount,
    peer: Option<SocketAddr>,
}
#[derive(Clone)]
pub struct BrioletteReceiver {
    next_tx_amount: Arc<RwLock<token::Amount>>,
    next_id: Arc<AtomicUsize>,
    // Maps the id to the next state
    // Currently, only one transaction at a time is supported.
    transactions: Arc<RwLock<HashMap<usize, TransactionState>>>,
    wallet: Arc<RwLock<WalletData>>,
}
impl BrioletteReceiver {
    pub async fn new(
        registrar_uri: String,
        clerk_uri: String,
        mint_uri: String,
        validate_uri: String,
    ) -> Result<Self, BrioletteErrorCode> {
        trace!("initializing wallet");
        let mut wd = WalletData::new(registrar_uri, clerk_uri, mint_uri, validate_uri)
            .map_err(|_| BrioletteErrorCode::InvalidMissingFields)?;
        assert!(wd.initialize_keys(b"receiver-wallet-001"));
        assert!(wd.initialize_credential().await);
        assert!(wd.synchronize().await);
        assert!(wd.get_tickets(5).await);

        // initialize, etc.
        // We start with a 0 amount since this is still a toy example.
        Ok(Self {
            next_id: Arc::new(AtomicUsize::new(1)),
            next_tx_amount: Arc::new(RwLock::new(token::Amount::default())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            wallet: Arc::new(RwLock::new(wd)),
        })
    }

    // A very simple interfaxce for UI or PoS to prepare for the next payer.
    // TODO: Replace with next_transaction() and setup all tx details.
    pub fn next_amount(&mut self, whole: u64, fractional: f32) {
        self.next_tx_amount = Arc::new(RwLock::new(token::Amount {
            whole: whole as i32,
            fractional,
            code: token::AmountType::TestToken.into(),
        }));
    }

    pub async fn initiate_impl(
        &self,
        request: &InitiateRequest,
        peer: Option<SocketAddr>,
    ) -> Result<InitiateReply, BrioletteError> {
        trace!("initiate: request = {:?}", &request);
        // 1. Receiver the version
        if request.version != Version::Current as i32 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }
        // If there is no epoch, we'll send one.
        if request.epoch.is_some() && request.epoch_signature.len() == 0 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        // 2. Setup Transaction data
        let amount = self.next_tx_amount.read().unwrap().clone();
        let tx_data = Transaction {
            total: amount.whole as f32 + amount.fractional,
            amount: amount,
            peer: peer,
        };

        let mut reply = InitiateReply::default();

        let tx_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        assert!(tx_id != std::usize::MAX - 1);
        reply.tx_id = tx_id.to_le_bytes().to_vec();
        // Determine if the next state is gossip or transact
        // And scope any mutexes grabbed.
        {
            let wallet = self.wallet.read().unwrap();
            let local_epoch = wallet.epoch.epoch;
            // TODO: Add EpochData::verify
            if request.epoch.is_none()
                || (request.epoch.is_some() && request.epoch.as_ref().unwrap().epoch != local_epoch)
            {
                trace!("peer epoch mismatch");
                self.transactions
                    .write()
                    .unwrap()
                    .insert(tx_id, TransactionState::Gossip(tx_data));
            } else {
                self.transactions
                    .write()
                    .unwrap()
                    .insert(tx_id, TransactionState::Transact(tx_data));
            }
            reply.epoch = wallet.epoch.epoch_update.as_ref().unwrap().data.clone();
            reply.epoch_signature = wallet
                .epoch
                .epoch_update
                .as_ref()
                .unwrap()
                .epoch_signature
                .clone();
            reply.ticket = Some(wallet.tickets.last().unwrap().clone().into());
            reply.items.push(TransactionItem {
                amount: Some(self.next_tx_amount.read().unwrap().clone()),
                name: "test item".to_string(),
                description: "Some transaction item".to_string(),
                supported_mint_public_keys: vec![], // default
            });
            // Only clear next_tx_amount in Transfer until we allow multiple simultaneous transactions.
        }

        // For each initiation, spawn a thread to check if it has timed out
        let tx_ref = self.transactions.clone();
        let timer_id = tx_id;
        task::spawn(async move {
            let id = timer_id.clone();
            info!("[{}] connection timer spawned", id);
            let transactions = tx_ref.clone();
            // 5 second between states
            let mut interval = time::interval(Duration::from_millis(5000));
            // The first tick is always immediate so we clear it out.
            interval.tick().await;
            loop {
                let last_state;
                if let Some(state) = transactions.read().unwrap().get(&id) {
                    last_state = state.clone();
                } else {
                    // We're done.
                    break;
                }
                interval.tick().await;
                debug!("[{}] connection timer fired", id);
                {
                    let state = transactions.read().unwrap().get(&id).unwrap().clone();
                    if state == last_state {
                        info!(
                            "[{}] transaction timed out at {}. aborting...",
                            id,
                            state.name()
                        );
                        transactions.write().unwrap().remove(&id);
                    }
                    if state.complete() {
                        info!("[{}] transaction completed!", id);
                        transactions.write().unwrap().remove(&id);
                    }
                }
            }
        });
        return Ok(reply);
    }

    pub fn gossip_impl(
        &self,
        request: &GossipRequest,
        peer: Option<SocketAddr>,
    ) -> Result<GossipReply, BrioletteError> {
        trace!("gossip: request = {:?}", &request);
        if request.tx_id.len() == 0 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        // Check transactions for id and peer
        let id = usize::from_le_bytes(
            request
                .tx_id
                .clone()
                .try_into()
                .unwrap_or(std::usize::MAX.to_le_bytes()),
        );
        let tx_data;
        if let Some(state) = self.transactions.read().unwrap().get(&id) {
            tx_data = state.inner();
        } else {
            // Unknown transaction
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTransactionId.into(),
            });
        }
        if peer != tx_data.peer {
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTransactionPeer.into(),
            });
        }
        let mut reply = GossipReply::default();
        // If their epoch is newer, then we should take their update.
        if let Some(peer_epoch_update) = request.epoch_update.as_ref() {
            let mut wallet = self.wallet.write().unwrap();
            let local_epoch = wallet.epoch.epoch;
            let peer_epoch = peer_epoch_update.data.as_ref().unwrap().epoch;
            if peer_epoch > local_epoch {
                if wallet.gossip_synchronize(request.epoch_update.as_ref().unwrap()) == false {
                    return Err(BrioletteError {
                        code: BrioletteErrorCode::InvalidEpochSignature.into(),
                    });
                }
            }
        } else {
            // If they didn't supply an epoch, then send ours back.
            let wallet = self.wallet.read().unwrap();
            reply.epoch_update = wallet.epoch.epoch_update.clone();
        }
        self.transactions
            .write()
            .unwrap()
            .insert(id, TransactionState::Transact(tx_data));

        return Ok(reply);
    }
    pub async fn transact_impl(
        &self,
        request: &TransactRequest,
        peer: Option<SocketAddr>,
    ) -> Result<TransactReply, BrioletteError> {
        trace!("transact: request = {:?}", &request);
        // Check transactions for id and peer
        let id = usize::from_le_bytes(
            request
                .tx_id
                .clone()
                .try_into()
                .unwrap_or(std::usize::MAX.to_le_bytes()),
        );
        let tx_data;
        if let Some(state) = self.transactions.read().unwrap().get(&id) {
            tx_data = state.inner();
        } else {
            // Unknown transaction
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTransactionId.into(),
            });
        }
        if peer != tx_data.peer {
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTransactionPeer.into(),
            });
        }
        // Check the proposal to see if it sums to the right amount and the tokens are valid.
        let mut reply = TransactReply::default();
        let mut total_amount = token::Amount::default();
        for method in request.methods.iter() {
            if self.wallet.read().unwrap().verify_tokens(&method.tokens) == false {
                error!("proposal had invalid tokens!");
                reply.accept = false;
                return Ok(reply);
            }
            for token in method.tokens.iter() {
                total_amount =
                    total_amount + token.descriptor.as_ref().unwrap().value.clone().unwrap();
            }
        }
        let total = total_amount.whole as f32 + total_amount.fractional;
        if total != tx_data.total || total_amount != tx_data.amount {
            error!(
                "proposed transfer did not add up: {} != {}",
                total, tx_data.total
            );
            reply.accept = false;
            return Ok(reply);
        }
        // TODO: Add optional validation support
        reply.accept = true;
        self.transactions
            .write()
            .unwrap()
            .insert(id, TransactionState::Transfer(tx_data));
        return Ok(reply);
    }

    pub async fn transfer_impl(
        &self,
        request: &TransferRequest,
        peer: Option<SocketAddr>,
    ) -> Result<TransferReply, BrioletteError> {
        trace!("transfer: request = {:?}", &request);
        // Check transactions for id and peer
        let id = usize::from_le_bytes(
            request
                .tx_id
                .clone()
                .try_into()
                .unwrap_or(std::usize::MAX.to_le_bytes()),
        );
        let tx_data;
        if let Some(state) = self.transactions.read().unwrap().get(&id) {
            tx_data = state.inner();
        } else {
            // Unknown transaction
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTransactionId.into(),
            });
        }
        if peer != tx_data.peer {
            return Err(BrioletteError {
                code: BrioletteErrorCode::UnknownTransactionPeer.into(),
            });
        }
        // In practice, this should check to make sure they are the same tokens. Instead, we'll
        // just make sure they still total the right amount, verify, and that the last recipient is
        // our ticket.
        let mut reply = TransferReply::default();
        let mut total_amount = token::Amount::default();
        // TODO: we forcibly validate, but that is not expected.
        if self.wallet.read().unwrap().verify_tokens(&request.tokens) == false {
            error!("proposal had invalid tokens!");
            reply.accepted = false;
            return Ok(reply);
        }
        let expected_ticket: token::SignedTicket = self
            .wallet
            .read()
            .unwrap()
            .tickets
            .last()
            .unwrap()
            .clone()
            .into();
        for token in request.tokens.iter() {
            total_amount = total_amount + token.descriptor.as_ref().unwrap().value.clone().unwrap();
            // Check that the last transaction is to our ticket.
            let tx_to = token
                .history
                .last()
                .unwrap()
                .transfer
                .as_ref()
                .unwrap()
                .recipient
                .as_ref()
                .unwrap()
                .ticket
                .as_ref()
                .unwrap();
            if tx_to.credential != expected_ticket.ticket.as_ref().unwrap().credential {
                error!("Tokens were not transferred to me!");
                reply.accepted = false;
                return Ok(reply);
            }
        }
        let total = total_amount.whole as f32 + total_amount.fractional;
        if total != tx_data.total || total_amount != tx_data.amount {
            error!(
                "proposed transfer did not add up: {} != {}",
                total, tx_data.total
            );
            reply.accepted = false;
            return Ok(reply);
        }
        // TODO: Add optional validation support
        reply.accepted = true;

        // Add the tokens to the wallet
        info!(
            "adding {} ({} {:?}) tokens to wallet",
            request.tokens.len(),
            total,
            total_amount.code
        );
        for token in &mut request.tokens.clone() {
            // TODO: Verify!
            self.wallet
                .write()
                .unwrap()
                .tokens
                .push(token.clone().into());
        }
        self.transactions
            .write()
            .unwrap()
            .insert(id, TransactionState::Complete(tx_data));

        return Ok(reply);
    }
}
