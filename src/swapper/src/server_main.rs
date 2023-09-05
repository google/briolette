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

use briolette_swapper::server::BrioletteSwapper;
use clap::Parser as ClapParser;
use log::*;
use tokio;

use briolette_proto::briolette::swapper::swapper_server::SwapperServer;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Address to listen on
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        default_value = "[::1]:50057"
    )]
    listen_address: String,
    // Registrar server URI
    #[arg(
        short = 'r',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50051"
    )]
    registrar_uri: String,
    // Mint server URI
    #[arg(
        short = 'm',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50053"
    )]
    mint_uri: String,
    // Clerk server URI
    #[arg(
        short = 'c',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50052"
    )]
    clerk_uri: String,
    // Validate server URI
    #[arg(
        short = 'v',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50055"
    )]
    validate_uri: String,
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
    info!("Setting up swapper server...");
    let swapper: BrioletteSwapper = BrioletteSwapper::new(
        args.registrar_uri,
        args.clerk_uri,
        args.mint_uri,
        args.validate_uri,
    )
    .await
    .unwrap();
    tonic::transport::Server::builder()
        .add_service(SwapperServer::new(swapper))
        .serve(addr)
        .await?;
    Ok(())
}
