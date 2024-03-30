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

use briolette_proto::briolette::registrar::registrar_server::RegistrarServer;
use briolette_registrar::server::BrioletteRegistrar;

use clap::Parser as ClapParser;
use std::path::PathBuf;
use tokio;
// Provides Registrar for ErrRegistrar

// Registrar secrets
// - Now - files
// - Future - Crypto APIs
// Registrar public
// - Now - from secret
// - Future - config server call (TTC gets all valid NAC public)
//
// So we need two registrar mains
// - Common TTC registrar
// - Example NAC registrar
// NAC registrar should provide:
// - TTC Registrar URI(s)
// - TTC Public Key(s)
// - TTC Group Public Key(s)
// So that a client can get their NAC then
// - Make a call to each TTC
// - Verify the reply credential
// Don't assume calls are over TLS but for gRPC they should be.
// The NAC could provide a trust root bundle for their client such that
// they aren't dependent on private CA registrars.
// So the common registrar protocol should be able to return TTC trust roots
// - This allows TTC Issuers to provide their officially supported GPKs
//   at any point - e.g., if a TTC GPK is being aged outGPK(s)
// - This allows NAC issuer to provide the TTC info to bootstrap
//   And also enable any other supports TTC
//  Seems like a split protocol will be better anyway
//  TTC _only_ needs a NAC signature.

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Logging verbosity
    #[arg(short = 'v', long, value_name = "NUMBER", default_value = "3")]
    verbosity: usize,
    // Logging quietude
    #[arg(short = 'q', long, action)]
    quiet: bool,
    #[arg(short = 'g', long, action, default_value = "true")]
    generate: bool,
    // Address to listen on
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        default_value = "[::1]:50051"
    )]
    listen_address: String,
    #[arg(
        short = 'n',
        long = "nac_issuer_gpk",
        value_name = "FILE",
        default_value = "data/registrar/nac_issuer.gpk"
    )]
    network_access_credential_issuer_group_public_key: PathBuf,
    // Path to Epoch secret signing key
    #[arg(
        short = 'N',
        long = "nac_issuer_secret",
        value_name = "FILE",
        default_value = "data/registrar/nac_issuer.sk"
    )]
    network_access_credential_issuer_secret_key: PathBuf,

    #[arg(
        short = 't',
        long = "ttc_issuer_gpk",
        value_name = "FILE",
        default_value = "data/registrar/ttc_issuer.gpk"
    )]
    token_transfer_credential_issuer_group_public_key: PathBuf,
    // Path to Epoch secret signing key
    #[arg(
        short = 'T',
        long = "ttc_issuer_secret",
        value_name = "FILE",
        default_value = "data/registrar/ttc_issuer.sk"
    )]
    token_transfer_credential_issuer_secret_key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    stderrlog::new()
        .quiet(args.quiet)
        .verbosity(args.verbosity)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()
        .unwrap();

    let registrar = BrioletteRegistrar::new(
        args.generate,
        &args.network_access_credential_issuer_secret_key,
        &args.network_access_credential_issuer_group_public_key,
        &args.token_transfer_credential_issuer_secret_key,
        &args.token_transfer_credential_issuer_group_public_key,
    );
    tonic::transport::Server::builder()
        .add_service(RegistrarServer::new(registrar))
        .serve(args.listen_address.parse().unwrap())
        .await?;
    Ok(())
}
