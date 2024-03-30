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

use briolette_crypto::v0;
use briolette_proto::briolette::registrar::{
    Algorithm, CredentialReply, RegisterReply, RegisterRequest,
};
use briolette_proto::briolette::Version;
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};

use log::{error, info, trace};
use std::path::Path;

#[derive(Debug, Default)]
pub struct BrioletteRegistrar {
    // In the future, an authorized hardware vendor may issue
    // the network credential to its hardware in the field.
    //
    // The currency operator would then issue the token credential
    // which is authenticated bu the network credential.
    network_secret_key: Vec<u8>, // TODO: Add more of these to reflect different hw groups.
    network_group_public_key: Vec<u8>,
    transfer_secret_key: Vec<u8>,
    transfer_group_public_key: Vec<u8>,
}

impl BrioletteRegistrar {
    fn read_or_generate_key(
        generate: bool,
        secret_key_file: &Path,
        group_public_key_file: &Path,
        sk: &mut Vec<u8>,
        gpk: &mut Vec<u8>,
    ) -> bool {
        let mut loaded = false;
        if let Ok(mut secret_key_in) = std::fs::read(secret_key_file) {
            if let Ok(mut group_public_key_in) = std::fs::read(group_public_key_file) {
                info!(
                    "loaded keys from disk: {}, {}",
                    secret_key_file.display(),
                    group_public_key_file.display()
                );
                sk.append(&mut secret_key_in);
                gpk.append(&mut group_public_key_in);
                loaded = true;
            }
        }
        if !loaded {
            if generate {
                // Generate a new secret key public key, and group key.
                info!(
                    "generating new issuer keypair: {}, {}",
                    secret_key_file.display(),
                    group_public_key_file.display()
                );
                let result = v0::generate_issuer_keypair(sk, gpk);
                if result == false {
                    error!("failed to generate issuer keypair");
                    return false;
                }
                // Attempt to update the supplied path with the new keys.
                if !secret_key_file.as_os_str().is_empty() {
                    std::fs::write(secret_key_file, sk).unwrap_or_else(|_| {
                        panic!(
                            "could not write secret key to: {:?}/{:?}",
                            std::env::current_dir().unwrap(),
                            secret_key_file
                        )
                    });
                }
                if !group_public_key_file.as_os_str().is_empty() {
                    std::fs::write(group_public_key_file, gpk).unwrap();
                }
                loaded = true;
            } else {
                error!("no issuer keypairs found and generation disabled!");
            }
        }
        return loaded;
    }

    pub fn new(
        generate: bool,
        network_secret_key_file: &Path,
        network_group_public_key_file: &Path,
        transfer_secret_key_file: &Path,
        transfer_group_public_key_file: &Path,
    ) -> Self {
        let mut network_secret_key: Vec<u8> = vec![];
        let mut network_group_public_key: Vec<u8> = vec![];
        let mut transfer_secret_key: Vec<u8> = vec![];
        let mut transfer_group_public_key: Vec<u8> = vec![];
        assert_eq!(
            BrioletteRegistrar::read_or_generate_key(
                generate,
                &network_secret_key_file,
                &network_group_public_key_file,
                &mut network_secret_key,
                &mut network_group_public_key
            ),
            true
        );
        assert_eq!(
            BrioletteRegistrar::read_or_generate_key(
                generate,
                &transfer_secret_key_file,
                &transfer_group_public_key_file,
                &mut transfer_secret_key,
                &mut transfer_group_public_key
            ),
            true
        );
        Self {
            network_secret_key,
            network_group_public_key,
            transfer_secret_key,
            transfer_group_public_key,
        }
    }
    // We always provide a non-async implementation for cleaner testing.
    // It also allows migration to different wrapping frameworks.
    pub fn register_call_impl(
        &self,
        request: &RegisterRequest,
    ) -> Result<RegisterReply, BrioletteError> {
        trace!("register_call: request = {:?}", &request);
        // 1. Validate the hwid signature
        if request.version != Version::Current.into() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidVersion.into(),
            });
        }
        if !request.hwid.is_some()
            || !request.hwid_signature.is_some()
            || !request.network_credential.is_some()
            || !request.transfer_credential.is_some()
        {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        let hwid = request.hwid.clone().unwrap();
        let hwid_signature = request.hwid_signature.clone().unwrap();
        let network_request = request.network_credential.clone().unwrap();
        let transfer_request = request.transfer_credential.clone().unwrap();

        // No verification occurs right now, so we fail if there is any!
        if hwid_signature.algorithm != Algorithm::None.into() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidHwidSignature.into(),
            });
        }
        // 2. Issue a network credential with the nonce of the token public key.
        let mut network_credential = vec![];
        let mut network_credential_signature = vec![];
        if v0::issue_credential(
            &network_request.public_key,
            &self.network_secret_key,
            &transfer_request.public_key,
            &mut network_credential,
            &mut network_credential_signature,
        ) == false
        {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidNetworkCredentialRequest.into(),
            });
        }

        // 3. Issue a token credential with the nonce of the signature-verified hwid
        //        let mut network_credential = vec![];
        let mut transfer_credential = vec![];
        let mut transfer_credential_signature = vec![];
        if v0::issue_credential(
            &transfer_request.public_key,
            &self.transfer_secret_key,
            &hwid.hw_id.clone(), // for Algorithm::NONE
            &mut transfer_credential,
            &mut transfer_credential_signature,
        ) == false
        {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidTokenCredentialRequest.into(),
            });
        }

        let reply = RegisterReply {
            network_credential: Some(CredentialReply {
                credential: network_credential,
                credential_signature: network_credential_signature,
                group_public_key: self.network_group_public_key.clone(),
            }),
            transfer_credential: Some(CredentialReply {
                credential: transfer_credential,
                credential_signature: transfer_credential_signature,
                group_public_key: self.transfer_group_public_key.clone(),
            }),
        };

        // 4. Return the new credentials.
        return Ok(reply);
    }
}
