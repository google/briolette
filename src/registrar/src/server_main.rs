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

use briolette_registrar::server::BrioletteRegistrar;
use std::path::Path;
use tokio;
// Provides Registrar for ErrRegistrar
use briolette_proto::briolette::registrar::registrar_server::RegistrarServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stderrlog::new()
        .quiet(false)
        .verbosity(3)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();
    let nsk = Path::new("data/registrar/net_issuer.sk");
    let ngpk = Path::new("data/registrar/net_issuer.gpk");
    let tsk = Path::new("data/registrar/ttc_issuer.sk");
    let tgpk = Path::new("data/registrar/ttc_issuer.gpk");
    let addr = "[::1]:50051".parse().unwrap();
    let registrar = BrioletteRegistrar::new(nsk, ngpk, tsk, tgpk);
    tonic::transport::Server::builder()
        .add_service(RegistrarServer::new(registrar))
        .serve(addr)
        .await?;
    Ok(())
}
