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

use briolette_mint::server::BrioletteMint;
use clap::Parser as ClapParser;
use log::*;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePublicKey;
use p256::SecretKey;
use rand_core::OsRng;
use std::path::{Path, PathBuf};
use tokio;

// Provides Mint for ErrMint
use briolette_proto::briolette::mint::mint_server::MintServer;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Address to listen on
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        default_value = "[::1]:50053"
    )]
    listen_address: String,
    // Path to mint public signing key
    #[arg(
        short = 'p',
        long,
        value_name = "FILE",
        default_value = "data/mint/mint.pk"
    )]
    mint_public_key: PathBuf,
    // Path to mint secret signing key
    #[arg(
        short = 's',
        long,
        value_name = "FILE",
        default_value = "data/mint/mint.sk"
    )]
    mint_secret_key: PathBuf,
    // Path to public Ticket Signing Key
    #[arg(
        short = 'T',
        long,
        value_name = "FILE",
        default_value = "data/clerk/ticket.pk"
    )]
    ticket_public_key: PathBuf,
    // Path to token transfer credential group public key
    #[arg(
        short = 'g',
        long = "ttc_group_public_key",
        value_name = "FILE",
        default_value = "data/registrar/ttc_issuer.gpk"
    )]
    token_transfer_credential_group_public_key: PathBuf,
    // TokenMap server URI
    #[arg(
        short = 'm',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50054"
    )]
    tokenmap_uri: String,
}

fn read_or_generate_key(
    secret_key_file: &Path,
    public_key_file: &Path,
    secret_key_out: &mut Vec<u8>,
) -> bool {
    let mut generate = true;
    if let Ok(mut secret_key_in) = std::fs::read(secret_key_file) {
        info!("loaded keys from disk: {}", secret_key_file.display());
        generate = false;
        secret_key_out.append(&mut secret_key_in);
    }
    if generate {
        // Generate a new secret key public key, and group key.
        info!(
            "generating new issuer keypair: {}",
            secret_key_file.display(),
        );
        let secret_key = SecretKey::random(&mut OsRng);
        //let sk = secret_key.to_pkcs8_der().unwrap();
        let signing_key: SigningKey = secret_key.clone().into();
        //secret_key_out.append(&mut sk.clone().as_bytes().to_vec());
        secret_key_out.append(&mut signing_key.to_bytes().to_vec());

        let pk: Vec<u8> = secret_key
            .public_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        // Attempt to update the supplied path with the new keys.
        if !secret_key_file.as_os_str().is_empty() {
            std::fs::write(secret_key_file, secret_key_out).unwrap();
        }
        if !public_key_file.as_os_str().is_empty() {
            std::fs::write(public_key_file, pk.clone()).unwrap();
        }
    }
    return true;
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
    let mut sk = vec![];
    assert!(read_or_generate_key(
        &args.mint_secret_key,
        &args.mint_public_key,
        &mut sk,
    ));
    let ttc_gpk = std::fs::read(&args.token_transfer_credential_group_public_key)
        .expect("No token transfer credential publick key available (run the registrar!)");
    let ticket_pk = std::fs::read(&args.ticket_public_key).expect("data/clerk not populated yet");
    let mint = BrioletteMint::new(sk, ttc_gpk, vec![ticket_pk], args.tokenmap_uri).unwrap();
    tonic::transport::Server::builder()
        .add_service(MintServer::new(mint))
        .serve(addr)
        .await?;
    Ok(())
}
