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
use log::*;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePublicKey;
use p256::SecretKey;
use rand_core::OsRng;
use std::path::Path;
use tokio;

// Provides Mint for ErrMint
use briolette_proto::briolette::mint::mint_server::MintServer;

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
    let addr = "[::1]:50053".parse().unwrap();
    let tokenmap_addr = "http://[::1]:50054".to_string();
    let mut sk = vec![];
    assert!(read_or_generate_key(
        &Path::new("data/mint/mint.sk"),
        &Path::new("data/mint/mint.pk"),
        &mut sk,
    ));
    let ttc_gpk = std::fs::read("data/registrar/ttc_issuer.gpk")
        .expect("data/registrar/wallet.ttc.gpk not populated yet");
    let ticket_pk = std::fs::read("data/clerk/ticket.pk").expect("data/clerk not populated yet");
    let mint = BrioletteMint::new(sk, ttc_gpk, vec![ticket_pk], tokenmap_addr).unwrap();
    tonic::transport::Server::builder()
        .add_service(MintServer::new(mint))
        .serve(addr)
        .await?;
    Ok(())
}
