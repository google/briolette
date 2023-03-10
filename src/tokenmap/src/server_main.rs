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

use briolette_tokenmap::server::BrioletteTokenMap;
use tokio;

use briolette_proto::briolette::tokenmap::token_map_server::TokenMapServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stderrlog::new()
        .quiet(false)
        .verbosity(3)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();
    let addr = "[::1]:50054".parse().unwrap();
    // TODO: load in the necessary public keys!
    //let ttc_gpk = std::fs::read("../registrar/data/wallet.ttc.gpk")
    //    .expect("registrar/data/wallet.ttc.gpk not populated yet");
    //let ticket_pk = std::fs::read("../clerk/data/ticket.pk").expect("clerk/data not populated yet");
    let tokenmap = BrioletteTokenMap::new(&"data/tokenmap.db".to_string()).await?;
    tonic::transport::Server::builder()
        .add_service(TokenMapServer::new(tokenmap))
        .serve(addr)
        .await?;
    Ok(())
}
