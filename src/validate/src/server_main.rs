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

use briolette_validate::server::BrioletteValidate;
use clap::Parser as ClapParser;
use log::*;
use std::path::PathBuf;
use tokio;

use briolette_proto::briolette::validate::validate_server::ValidateServer;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Address to listen on
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        default_value = "[::1]:50055"
    )]
    listen_address: String,
    // Path to Epoch public signing key
    #[arg(
        short = 'E',
        long,
        value_name = "FILE",
        default_value = "data/clerk/epoch.pk"
    )]
    epoch_signing_public_key: PathBuf,
    // TokenMap server URI
    #[arg(
        short = 'm',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50054"
    )]
    tokenmap_uri: String,
    // Clerk server URI
    #[arg(
        short = 'c',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50052"
    )]
    clerk_uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stderrlog::new()
        .quiet(false)
        .verbosity(1)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();
    let args = Args::parse();
    let addr = args.listen_address.parse().unwrap();
    let epoch_pk =
        std::fs::read(&args.epoch_signing_public_key).expect("data/clerk not populated yet");
    info!("Fetching initial EpochUpdate from {}", args.clerk_uri);
    if let Ok(eu) = BrioletteValidate::fetch_epoch_update(&args.clerk_uri, &epoch_pk).await {
        info!("Setting up server...");
        let validate = BrioletteValidate::new(&eu).await.unwrap();
        // TODO(redpig) add a task which fetches the new EpochUpdates after the defined interval
        tonic::transport::Server::builder()
            .add_service(ValidateServer::new(validate))
            .serve(addr)
            .await?;
    } else {
        error!("Failed to acquire a valid EpochUpdate!");
        assert!(false);
    }
    Ok(())
}
