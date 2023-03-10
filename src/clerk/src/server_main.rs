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
use log::info;
use std::path::Path;
use tokio;

// Provides Clerk for ErrClerk
use briolette_proto::briolette::clerk::clerk_server::ClerkServer;
use elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::ecdsa::VerifyingKey;
use p256::{PublicKey, SecretKey};
// TODO(wad) replace with a trait and SeedableRng
use rand_core::OsRng;

fn read_or_generate_key(secret_key_file: &Path, public_key_file: &Path, pk: &mut Vec<u8>) -> bool {
    let mut generate = true;
    if let Ok(secret_key_in) = std::fs::read(secret_key_file) {
        info!("loaded keys from disk: {}", secret_key_file.display());
        generate = false;
        let sk: SecretKey = SecretKey::from_pkcs8_der(secret_key_in.as_slice()).unwrap();
        let public_key = sk.public_key();
        pk.append(&mut public_key.to_public_key_der().unwrap().into_vec().clone());
    } else if let Ok(mut public_key_in) = std::fs::read(public_key_file) {
        info!("loaded keys from disk: {}", public_key_file.display());
        generate = false;
        pk.append(&mut public_key_in);
    }
    if generate {
        // Generate a new secret key public key, and group key.
        info!(
            "generating new issuer keypair: {}, {}",
            secret_key_file.display(),
            public_key_file.display()
        );
        let secret_key = SecretKey::random(&mut OsRng);
        let sk = secret_key.to_pkcs8_der().unwrap();
        pk.append(
            &mut secret_key
                .public_key()
                .to_public_key_der()
                .unwrap()
                .into_vec(),
        );
        // Attempt to update the supplied path with the new keys.
        if !secret_key_file.as_os_str().is_empty() {
            std::fs::write(secret_key_file, sk.as_bytes()).unwrap();
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

    let addr = "[::1]:50052".parse().unwrap();
    let tokenmap_uri = "http://[::1]:50054".to_string();
    // If there is a key in data, use it. Otherwise generate it.

    let mut pk: Vec<u8> = vec![];
    read_or_generate_key(
        &Path::new("data/epoch.sk"),
        &Path::new("data/epoch.pk"),
        &mut pk,
    );
    let epoch_pk = PublicKey::from_public_key_der(pk.as_slice()).unwrap();
    let epoch_vk: VerifyingKey = epoch_pk.into();
    let clerk;
    if let Ok(loaded_clerk) = BrioletteClerk::load(Path::new("data/clerk.state")) {
        clerk = loaded_clerk;
    } else {
        clerk = BrioletteClerk::new(&mut OsRng, &epoch_vk, tokenmap_uri);
        clerk.store(Path::new("data/clerk.state")).unwrap();
        clerk.write_public_key(Path::new("data/ticket.pk")).unwrap();
    }
    tonic::transport::Server::builder()
        .add_service(ClerkServer::new(clerk))
        .serve(addr)
        .await?;
    Ok(())
}
