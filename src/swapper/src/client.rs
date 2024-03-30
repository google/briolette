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

use briolette_proto::briolette::swapper::swapper_client::SwapperClient;
use briolette_proto::BrioletteClientHelper;

use briolette_proto::briolette::swapper::{GetDestinationRequest, SwapTokensRequest};
use briolette_proto::briolette::token;
use briolette_wallet::{Wallet, WalletData};

use prost::Message;
use tokio;
use tonic::transport::Uri;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SwapperClient::multiconnect(&Uri::try_from("http://[::1]:50057")?).await?;
    let registrar_uri = "http://[::1]:50051".to_string();
    let clerk_uri = "http://[::1]:50052".to_string();
    let mint_uri = "http://[::1]:50053".to_string();
    let validate_uri = "http://[::1]:50055".to_string();
    let mut wallet = WalletData::new(registrar_uri, clerk_uri, mint_uri, validate_uri)?;
    assert!(wallet.initialize_keys(b"swapper-client-wallet-001"));
    assert!(wallet.initialize_credential().await);
    assert!(wallet.synchronize().await);
    assert!(wallet.get_tickets(1).await);
    assert!(wallet.withdraw(5).await);
    let dst_request = GetDestinationRequest::default();

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

    println!("Calling swapper: {:?}", dst_request);
    let dst_response = client.get_destination(dst_request).await?;
    println!("Swapper replied: {:?}", dst_response);

    let msg = dst_response.into_inner();
    let destination = msg.swap_ticket.as_ref().unwrap();

    // Swap some tokens
    assert!(wallet.transfer(5, destination.encode_to_vec()));
    let transferred = wallet
        .pending_tokens
        .iter()
        .map(|t| token::Token::decode(t.as_slice()).unwrap())
        .collect();

    let mut swap_request = SwapTokensRequest::default();
    swap_request.tokens = transferred;

    println!("Calling swapper: {:?}", swap_request);
    let swap_response = client.swap_tokens(swap_request).await?;
    println!("Swapper replied: {:?}", swap_response);
    let swaps = swap_response.into_inner().tokens;
    assert!(swaps.len() == 5);
    wallet.pending_tokens.clear();
    for t in swaps {
        wallet.tokens.push(t.into());
    }
    // TODO: check the credential
    assert!(wallet.validate().await);

    Ok(())
}
