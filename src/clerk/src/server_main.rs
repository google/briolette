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

use briolette_clerk::server::BrioletteClerk;
use clap::Parser as ClapParser;
use log::info;
use std::path::{Path, PathBuf};
use tokio;

// Provides Clerk for ErrClerk
use briolette_proto::briolette::clerk::clerk_server::ClerkServer;
use elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::ecdsa::VerifyingKey;
use p256::{PublicKey, SecretKey};
// TODO(wad) replace with a trait and SeedableRng
use rand_core::OsRng;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Address to listen on
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        default_value = "[::1]:50052"
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
    // Path to Epoch secret signing key
    #[arg(
        short = 'e',
        long,
        value_name = "FILE",
        default_value = "data/clerk/epoch.sk"
    )]
    epoch_signing_secret_key: PathBuf,
    // Path to private/secret Ticket Signing Key
    #[arg(
        short = 't',
        long,
        value_name = "FILE",
        default_value = "data/clerk/ticket.sk"
    )]
    ticket_signing_secret_key: PathBuf,
    // Path to public Ticket Signing Key
    #[arg(
        short = 'T',
        long,
        value_name = "FILE",
        default_value = "data/clerk/ticket.pk"
    )]
    ticket_signing_public_key: PathBuf,
    // TokenMap server URI
    #[arg(
        short = 'm',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50054"
    )]
    tokenmap_uri: String,
    // Data file to store known epoch in
    #[arg(
        short = 'd',
        long,
        value_name = "FILE",
        default_value = "data/clerk/epoch.state"
    )]
    epoch_data: PathBuf,
}

fn read_or_generate_key(
    secret_key_file: &Path,
    public_key_file: &Path,
    pk: &mut Vec<u8>,
    sk: &mut Vec<u8>,
) -> bool {
    let mut generate = true;
    if let Ok(secret_key_in) = std::fs::read(secret_key_file) {
        info!("loaded keys from disk: {}", secret_key_file.display());
        generate = false;
        sk.append(&mut secret_key_in.clone());
        let nsk: SecretKey = SecretKey::from_pkcs8_der(secret_key_in.as_slice()).unwrap();
        let public_key = nsk.public_key();
        pk.append(&mut public_key.to_public_key_der().unwrap().into_vec().clone());
    }
    if generate {
        // Generate a new secret key public key, and group key.
        info!(
            "generating new issuer keypair: {}, {}",
            secret_key_file.display(),
            public_key_file.display()
        );
        let secret_key = SecretKey::random(&mut OsRng);
        let nsk = secret_key.to_pkcs8_der().unwrap();
        pk.append(
            &mut secret_key
                .public_key()
                .to_public_key_der()
                .unwrap()
                .into_vec(),
        );
        sk.append(&mut nsk.clone().as_bytes().to_vec());
        // Attempt to update the supplied path with the new keys.
        if !secret_key_file.as_os_str().is_empty() {
            std::fs::write(secret_key_file, nsk.as_bytes()).unwrap();
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
    // If there is a key in data, use it. Otherwise generate it.

    let mut pk: Vec<u8> = vec![];
    let mut epoch_sk: Vec<u8> = vec![];
    read_or_generate_key(
        &args.epoch_signing_secret_key,
        &args.epoch_signing_public_key,
        &mut pk,
        &mut epoch_sk,
    );
    let mut ticket_pk: Vec<u8> = vec![];
    let mut ticket_sk: Vec<u8> = vec![];
    read_or_generate_key(
        &args.ticket_signing_secret_key,
        &args.ticket_signing_public_key,
        &mut ticket_pk,
        &mut ticket_sk,
    );
    let epoch_pk = PublicKey::from_public_key_der(pk.as_slice()).unwrap();
    let epoch_vk: VerifyingKey = epoch_pk.into();
    let clerk;
    if let Ok(loaded_clerk) = BrioletteClerk::load(&args.epoch_data) {
        clerk = loaded_clerk;
    } else {
        clerk = BrioletteClerk::new(&ticket_sk, &epoch_vk, args.tokenmap_uri);
        clerk.store(&args.epoch_data).unwrap();
        clerk
            .write_public_key(&args.ticket_signing_public_key)
            .unwrap();
    }
    tonic::transport::Server::builder()
        .add_service(ClerkServer::new(clerk))
        .serve(addr)
        .await?;
    Ok(())
}
