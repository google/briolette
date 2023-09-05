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

use briolette_proto::briolette::tokenmap::token_map_server::TokenMapServer;
use briolette_tokenmap::server::BrioletteTokenMap;
use clap::Parser as ClapParser;
use std::path::PathBuf;
use tokio;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Address to listen on
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        default_value = "[::1]:50054"
    )]
    listen_address: String,
    // Path to Epoch public signing key
    #[arg(
        short = 'D',
        long,
        value_name = "FILE",
        default_value = "data/tokenmap/tokenmap.db"
    )]
    database: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stderrlog::new()
        .quiet(false)
        .verbosity(3)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();
    let args = Args::parse();
    let addr = args.listen_address.parse().unwrap();
    let tokenmap =
        BrioletteTokenMap::new(&args.database.as_path().to_str().unwrap().to_string()).await?;
    tonic::transport::Server::builder()
        .add_service(TokenMapServer::new(tokenmap))
        .serve(addr)
        .await?;
    Ok(())
}
