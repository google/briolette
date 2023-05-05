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
use log::*;
use tokio;

use briolette_proto::briolette::swapper::swapper_server::SwapperServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stderrlog::new()
        .quiet(false)
        .verbosity(1)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();
    let addr = "[::1]:50057".parse().unwrap();
    let registrar_uri = "http://[::1]:50051".to_string();
    let clerk_uri = "http://[::1]:50052".to_string();
    let mint_uri = "http://[::1]:50053".to_string();
    let validate_uri = "http://[::1]:50055".to_string();
    info!("Setting up swapper server...");
    let swapper: BrioletteSwapper = BrioletteSwapper::new(registrar_uri, clerk_uri, mint_uri, validate_uri)
        .await
        .unwrap();
    tonic::transport::Server::builder()
        .add_service(SwapperServer::new(swapper))
        .serve(addr)
        .await?;
    Ok(())
}
