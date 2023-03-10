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

use briolette_proto::briolette::receiver::receiver_client::ReceiverClient;
use briolette_proto::briolette::receiver::*;
use briolette_proto::briolette::token;

use briolette_wallet::{Wallet, WalletData};
use prost::Message;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ReceiverClient::connect("http://[::1]:50056").await?;
    let registrar_uri = "http://[::1]:50051".to_string();
    let clerk_uri = "http://[::1]:50052".to_string();
    let mint_uri = "http://[::1]:50053".to_string();
    let validate_uri = "http://[::1]:50054".to_string();
    let mut wallet = WalletData::new(registrar_uri, clerk_uri, mint_uri, validate_uri);
    assert!(wallet.initialize_keys(b"client-wallet-001"));
    assert!(wallet.initialize_credential().await);
    assert!(wallet.synchronize().await);
    assert!(wallet.get_tickets(5).await);
    assert!(wallet.withdraw(5).await);
    let request = InitiateRequest::default();

    // TODO: make sending this configurable on the command line
    /*
    request.epoch = wallet.epoch.epoch_update.as_ref().unwrap().data.clone();
    request.epoch_signature = wallet
        .epoch
        .epoch_update
        .as_ref()
        .unwrap()
        .epoch_signature
        .clone();
    */

    println!("Calling receiver: {:?}", request);
    let response = client.initiate(request).await?;
    println!("Receiver replied: {:?}", response);

    let msg = response.into_inner();
    let tx_id = msg.tx_id;
    let destination = msg.ticket.clone().unwrap();
    let mut total = 0;
    for item in msg.items.iter() {
        if let Some(val) = item.amount.as_ref() {
            total += val.whole;
            // TODO: Wire up fractional and splits.
        }
    }

    let gossip_request = GossipRequest {
        tx_id: tx_id.clone(),
        epoch_update: None,
    };
    println!("Calling receiver: {:?}", gossip_request);
    let gossip_response = client.gossip(gossip_request).await?;
    println!("Receiver replied: {:?}", gossip_response);

    // Propose a transfer
    // TODO: Roll this into wallet
    // Get the last two tokens
    let tokens = wallet
        .tokens
        .iter()
        .rev()
        .take(total as usize)
        .map(|te| token::Token::decode(te.token.as_slice()).unwrap())
        .collect();
    let transact_request = TransactRequest {
        tx_id: tx_id.clone(),
        methods: vec![TransactionItemMethod {
            tokens: tokens,
            mint_public_key: vec![],
        }],
    };
    println!("Calling receiver: {:?}", transact_request);
    let transact_response = client.transact(transact_request).await?;
    println!("Receiver replied: {:?}", transact_response);
    assert!(transact_response.into_inner().accept);

    assert!(wallet.transfer(total as u32, destination.encode_to_vec()));
    let transferred = wallet
        .pending_tokens
        .iter()
        .map(|t| token::Token::decode(t.as_slice()).unwrap())
        .collect();
    let transfer_request = TransferRequest {
        tx_id: tx_id.clone(),
        tokens: transferred,
    };
    println!("Calling receiver: {:?}", transfer_request);
    let transfer_response = client.transfer(transfer_request).await?;
    println!("Receiver replied: {:?}", transfer_response);
    assert!(transfer_response.into_inner().accepted);
    wallet.pending_tokens.clear();

    Ok(())
}
