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

tonic::include_proto!("briolette.clerk");
use crate::briolette::ErrorCode as BrioletteErrorCode;
use crate::vec_utils;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use prost::Message;
use sha2::{Digest, Sha256};

pub trait EpochVerify {
    fn verify(&self, public_key_der: &Vec<u8>) -> Result<bool, BrioletteErrorCode>;
}

impl EpochVerify for EpochUpdate {
    fn verify(&self, public_key_der: &Vec<u8>) -> Result<bool, BrioletteErrorCode> {
        let pk: PublicKey;
        if let Ok(maybe_pk) = PublicKey::from_public_key_der(public_key_der) {
            pk = maybe_pk;
        } else {
            return Err(BrioletteErrorCode::UnparseablePublicKey);
        }
        let vk: VerifyingKey = pk.into();
        if let Ok(signature) = Signature::try_from(self.epoch_signature.as_slice()) {
            // Confirm signature over data
            if let Ok(_r) = vk.verify(
                self.data.as_ref().unwrap().encode_to_vec().as_slice(),
                &signature,
            ) {
                // Confirm that the eed hash matches what was signed.
                let eed_hash =
                    Sha256::digest(self.extended_data.as_ref().unwrap().encode_to_vec()).to_vec();
                if vec_utils::vec_equal(
                    &eed_hash,
                    &self.data.as_ref().unwrap().extended_epoch_data_hash,
                ) == true
                {
                    return Ok(true);
                }
            }
        }
        Err(BrioletteErrorCode::InvalidEpochSignature)
    }
}
