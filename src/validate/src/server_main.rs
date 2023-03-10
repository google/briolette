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
use log::*;
use tokio;

use briolette_proto::briolette::validate::validate_server::ValidateServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stderrlog::new()
        .quiet(false)
        .verbosity(1)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();
    let addr = "[::1]:50055".parse().unwrap();
    let tokenmap_uri = "http://[::1]:50054".to_string();
    let clerk_uri = "http://[::1]:50052".to_string();
    let epoch_pk = std::fs::read("../clerk/data/epoch.pk").expect("clerk/data not populated yet");
    info!("Setting up server...");
    let validate = BrioletteValidate::new(clerk_uri, tokenmap_uri, epoch_pk)
        .await
        .unwrap();
    tonic::transport::Server::builder()
        .add_service(ValidateServer::new(validate))
        .serve(addr)
        .await?;
    Ok(())
}
