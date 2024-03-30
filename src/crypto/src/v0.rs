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

pub(crate) mod native {

    pub const MODBYTES_256_56: usize = 32;
    pub const CREDENTIAL_LENGTH: usize = 260;
    pub const CREDENTIAL_SIGNATURE_LENGTH: usize = 64;
    pub const SIGNATURE_LENGTH: usize = 356;
    pub const SIGNATURE_WITH_NYM_LENGTH: usize = 421;
    pub const ISSUER_SECRET_KEY_LENGTH: usize = 64;
    pub const ISSUER_GROUP_PUBLIC_KEY_LENGTH: usize = 258;

    pub const WALLET_SECRET_KEY_LENGTH: usize = 32;
    pub const WALLET_PUBLIC_KEY_LENGTH: usize = 161;
    extern "C" {
        pub fn issue_credential(
            member_public_key: *const libc::c_uchar,
            member_public_key_len: libc::c_ulong,
            issuer_secret_key: *const libc::c_uchar,
            issuer_secret_key_len: libc::c_ulong,
            credential_out: *mut libc::c_uchar,
            credential_out_len: libc::c_ulong,
            credential_signature_out: *mut libc::c_uchar,
            credential_signature_out_len: libc::c_ulong,
            nonce: *const libc::c_uchar,
            nonce_len: libc::c_ulong,
        ) -> libc::c_int;

        pub fn generate_issuer_keypair(
            issuer_secret_key: *const libc::c_uchar,
            issuer_secret_key_len: libc::c_ulong,
            group_public_key: *const libc::c_uchar,
            group_public_key_len: libc::c_ulong,
        ) -> libc::c_int;

        pub fn generate_wallet_keypair(
            secret_key: *const libc::c_uchar,
            secret_key_len: libc::c_ulong,
            public_key: *const libc::c_uchar,
            public_key_len: libc::c_ulong,
            nonce: *const libc::c_uchar,
            nonce_len: libc::c_ulong,
        ) -> libc::c_int;
        pub fn verify_signature(
            signature: *const libc::c_uchar,
            signature_len: libc::c_ulong,
            message: *const libc::c_uchar,
            message_len: libc::c_ulong,
            group_public_key: *const libc::c_uchar,
            group_public_key_len: libc::c_ulong,
            req_signer_cred: *const libc::c_uchar,
            req_signer_cred_len: libc::c_ulong,
            basename: *const libc::c_uchar,
            basename_len: libc::c_ulong,
        ) -> libc::c_int;
        pub fn sign(
            message: *const libc::c_uchar,
            message_len: libc::c_ulong,
            basename: *const libc::c_uchar,
            basename_len: libc::c_ulong,
            credential: *const libc::c_uchar,
            credential_len: libc::c_ulong,
            secret_key: *const libc::c_uchar,
            secret_key_len: libc::c_ulong,
            randomize_credential: libc::c_int,
            out: *const libc::c_uchar,
            out_len: libc::c_ulong,
        ) -> libc::c_int;
        pub fn randomize_credential(
            credential: *const libc::c_uchar,
            credential_len: libc::c_ulong,
            random_credential: *const libc::c_uchar,
            random_credential_len: libc::c_ulong,
        ) -> libc::c_int;
        pub fn credential_in_group(
            credential: *const libc::c_uchar,
            credential_len: libc::c_ulong,
            group_public_key: *const libc::c_uchar,
            group_public_key_len: libc::c_ulong,
        ) -> libc::c_int;
    }
}

pub fn generate_wallet_keypair(
    nonce: &Vec<u8>,
    secret_key: &mut Vec<u8>,
    public_key: &mut Vec<u8>,
) -> bool {
    if nonce.len() == 0 {
        return false;
    }

    // Make sure these are allocated before grabbing the pointer.
    secret_key.resize(native::WALLET_SECRET_KEY_LENGTH, 0);
    public_key.resize(native::WALLET_PUBLIC_KEY_LENGTH, 0);
    let sk = secret_key.as_mut_ptr();
    let pk = public_key.as_mut_ptr();
    let n = nonce.as_ptr();

    let ret;
    unsafe {
        ret = native::generate_wallet_keypair(
            sk,
            secret_key.len() as u64,
            pk,
            public_key.len() as u64,
            n,
            nonce.len() as u64,
        );
        if ret != 0 {
            secret_key.clear();
            public_key.clear();
        }
    }
    ret == 0
}

pub fn generate_issuer_keypair(
    issuer_secret_key: &mut Vec<u8>,
    group_public_key: &mut Vec<u8>,
) -> bool {
    // Make sure these are allocated before grabbing the pointer.
    issuer_secret_key.resize(native::ISSUER_SECRET_KEY_LENGTH, 0);
    group_public_key.resize(native::ISSUER_GROUP_PUBLIC_KEY_LENGTH, 0);
    let isk = issuer_secret_key.as_mut_ptr();
    let gpk = group_public_key.as_mut_ptr();

    let ret;
    unsafe {
        ret = native::generate_issuer_keypair(
            isk,
            issuer_secret_key.len() as u64,
            gpk,
            group_public_key.len() as u64,
        );
        if ret != 0 {
            issuer_secret_key.clear();
            group_public_key.clear();
        }
    }
    ret == 0
}

pub fn issue_credential(
    member_public_key: &Vec<u8>,
    issuer_secret_key: &Vec<u8>,
    nonce: &Vec<u8>,
    credential_out: &mut Vec<u8>,
    credential_signature_out: &mut Vec<u8>,
) -> bool {
    let mpk = member_public_key.as_ptr();
    let isk = issuer_secret_key.as_ptr();
    let n = nonce.as_ptr();
    // Make sure these are allocated before grabbing the pointer.
    credential_out.resize(native::CREDENTIAL_LENGTH, 0);
    credential_signature_out.resize(native::CREDENTIAL_SIGNATURE_LENGTH, 0);
    let cout = credential_out.as_mut_ptr();
    let cso = credential_signature_out.as_mut_ptr();

    let ret;
    unsafe {
        ret = native::issue_credential(
            mpk,
            member_public_key.len() as u64,
            isk,
            issuer_secret_key.len() as u64,
            cout,
            credential_out.len() as u64,
            cso,
            credential_signature_out.len() as u64,
            n,
            nonce.len() as u64,
        );
        if ret != 0 {
            credential_out.clear();
            credential_signature_out.clear();
        }
    }
    ret == 0
}

// Verifies an ECDAA member signature optionally with the supplied
// basename and optionally enforcing the signing credential is |signing_credential|.
pub fn verify(
    group_public_key: &Vec<u8>,
    basename: &Option<Vec<u8>>,
    signing_credential: &Option<Vec<u8>>,
    signature: &Vec<u8>,
    message: &Vec<u8>,
) -> bool {
    if group_public_key.len() == 0 || signature.len() == 0 || message.len() == 0 {
        return false;
    }
    let gpk = group_public_key.as_ptr();
    let sig = signature.as_ptr();
    let msg = message.as_ptr();
    let bsn;
    let bsn_len: u64;
    if let Some(bsn_vec) = basename {
        // Will this go out of scope?
        bsn = bsn_vec.as_ptr();
        bsn_len = bsn_vec.len() as u64;
    } else {
        bsn = std::ptr::null();
        bsn_len = 0;
    }
    let rsc;
    let rsc_len: u64;
    if let Some(rsc_vec) = signing_credential {
        rsc = rsc_vec.as_ptr();
        rsc_len = rsc_vec.len() as u64;
    } else {
        rsc = std::ptr::null();
        rsc_len = 0;
    }

    let ret;
    unsafe {
        ret = native::verify_signature(
            sig,
            signature.len() as u64,
            msg,
            message.len() as u64,
            gpk,
            group_public_key.len() as u64,
            rsc,
            rsc_len as u64,
            bsn,
            bsn_len,
        );
    }
    ret == 0
}

pub fn sign(
    message: &Vec<u8>,
    credential: &Vec<u8>,
    secret_key: &Vec<u8>,
    basename: &Option<Vec<u8>>,
    randomize_credential: bool,
    signature: &mut Vec<u8>,
) -> bool {
    if message.len() == 0 || credential.len() == 0 || secret_key.len() == 0 {
        return false;
    }
    if let Some(bsn) = basename {
        if bsn.len() == 0 {
            return false;
        }
    }
    // Expand the signature to the correct length,
    if basename.is_some() {
        signature.resize(native::SIGNATURE_WITH_NYM_LENGTH, 0);
    } else {
        signature.resize(native::SIGNATURE_LENGTH, 0);
    }
    let msg = message.as_ptr();
    let crd = credential.as_ptr();
    let sk = secret_key.as_ptr();
    let sig = signature.as_mut_ptr();
    let rc;
    if randomize_credential {
        rc = 1
    } else {
        rc = 0;
    }
    let bsn;
    let bsn_len: u64;
    if let Some(bsn_vec) = basename {
        // Will this go out of scope?
        bsn = bsn_vec.as_ptr();
        bsn_len = bsn_vec.len() as u64;
    } else {
        bsn = std::ptr::null();
        bsn_len = 0;
    }

    let ret;
    unsafe {
        ret = native::sign(
            msg,
            message.len() as u64,
            bsn,
            bsn_len as u64,
            crd,
            credential.len() as u64,
            sk,
            secret_key.len() as u64,
            rc,
            sig,
            signature.len() as u64,
        );
        if ret != 0 {
            signature.clear();
        }
    }
    ret == 0
}

pub fn randomize_credential(credential: &Vec<u8>, credential_out: &mut Vec<u8>) -> bool {
    if credential.len() == 0 {
        return false;
    }
    let cred = credential.as_ptr();
    // Make sure these are allocated before grabbing the pointer.
    credential_out.resize(native::CREDENTIAL_LENGTH, 0);
    let cout = credential_out.as_mut_ptr();
    let ret;
    unsafe {
        ret = native::randomize_credential(
            cred,
            credential.len() as u64,
            cout,
            credential_out.len() as u64,
        );
        if ret != 0 {
            credential_out.clear();
        }
    }
    ret == 0
}

// TODO: wrap the Vec<u8>s in a struct so we can use From/Into
pub fn credential_from_signature(signature: &Vec<u8>, credential: &mut Vec<u8>) -> bool {
    if signature.len() < native::SIGNATURE_LENGTH {
        return false;
    }
    credential.resize(native::CREDENTIAL_LENGTH, 0);
    let offset = 2 * native::MODBYTES_256_56;
    let end = offset + native::CREDENTIAL_LENGTH;
    credential.copy_from_slice(&signature[offset..end]);
    return true;
}

// Removes the credential saving 260 bytes
pub fn deflate_signature(signature: &mut Vec<u8>) {
    if signature.len() < native::SIGNATURE_LENGTH {
        return;
    }
    let offset = 2 * native::MODBYTES_256_56;
    let end = offset + native::CREDENTIAL_LENGTH;
    signature.drain(offset..end);
}

pub fn inflate_signature(credential: &Vec<u8>, signature: &mut Vec<u8>) {
    let offset = 2 * native::MODBYTES_256_56;
    let rhs = signature.split_off(offset);
    signature.extend_from_slice(credential.as_slice());
    signature.extend_from_slice(rhs.as_slice());
}

pub fn credential_in_group(credential: &Vec<u8>, group_public_key: &Vec<u8>) -> bool {
    if credential.len() == 0 || group_public_key.len() == 0 {
        return false;
    }
    let cred = credential.as_ptr();
    let gpk = group_public_key.as_ptr();
    let ret;
    unsafe {
        ret = native::credential_in_group(
            cred,
            credential.len() as u64,
            gpk,
            group_public_key.len() as u64,
        );
    }
    ret == 0
}

use thiserror::Error;
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Low level {0:?}() failed {1:?})")]
    LowLevelError(String, u64),
    #[error("I/O Error: {0}")]
    IOError(String),
}

/* TODO(redpig) encapsulate key interactions idiomatically
pub trait Keypair {
  fn public_key(&self) -> &Vec<u8>;
  fn secret_key(&self) -> &Vec<u8>;

  fn generate(&mut self) -> Result<(), CryptoError>;
  // sign
  // credentials should be diff than keypairs so we can deal with basename sep.
  // ...

  fn serialize(&self) -> Result<Vec<u8>, CryptoError>;
  fn deserialize(&mut self, bytes: Vec<u8>) -> Result<(), CryptoError>;

  fn load(&mut self, sk: &Path, pk: &Path) -> Result<(), CryptoError>;
  fn store(&self, sk: &Path, pk: &Path) -> Result<(), CryptoError>;
}


#[derive(Debug)]
pub struct IssuerKeypair {
  secret: Vec<u8>,
  group_public: Vec<u8>,
}

impl Keypair for IssuerKeypair {
  fn public_key(&self) -> &Vec<u8> {
    self.group_public
  }

  fn secret(&self) -> &Vec<u8> {
    self.secret
  }

  pub fn generate(&mut self) -> Result<(), CryptoError> {
    let result = generate_issuer_keypair(self.secret, self.group_public);
    // TOOD(redpig) pass through Err
    if result == false {
      return Err(CryptoError::LowLevelError("generate_issuer_keypair", 1));
    }
    Ok(())
  }
}

*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_credential_valid_issuance() {
        let issuer_sk = std::fs::read("testdata/issuer.sk").unwrap();
        let member_pk = std::fs::read("testdata/member.pk").unwrap();
        let nonce = std::fs::read("testdata/nonce").unwrap();

        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        let result = issue_credential(&member_pk, &issuer_sk, &nonce, &mut cred, &mut cred_sig);
        // TODO: Verify the credential signature
        std::fs::write("member.cred", cred).unwrap();
        std::fs::write("member.cred.sig", cred_sig).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn issue_credential_bad_nonce() {
        let issuer_sk = std::fs::read("testdata/issuer.sk").unwrap();
        let member_pk = std::fs::read("testdata/member.pk").unwrap();
        let nonce = vec![0, 1, 2, 3, 4];

        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        let result = issue_credential(&member_pk, &issuer_sk, &nonce, &mut cred, &mut cred_sig);
        assert_eq!(result, false);
    }

    #[test]
    fn issuer_generate_keypair_basic() {
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(issuer_sk.len(), native::ISSUER_SECRET_KEY_LENGTH);
        assert_eq!(group_pk.len(), native::ISSUER_GROUP_PUBLIC_KEY_LENGTH);
        assert_eq!(ret, true);
    }
    #[test]
    fn wallet_generate_keypair_basic() {
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes();
        let ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(sk.len(), native::WALLET_SECRET_KEY_LENGTH);
        assert_eq!(pk.len(), native::WALLET_PUBLIC_KEY_LENGTH);
        assert_eq!(ret, true);
    }
    #[test]
    fn new_credential_from_generated_keys() {
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);

        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);

        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);
        assert_eq!(cred.len(), native::CREDENTIAL_LENGTH);
        assert_eq!(cred_sig.len(), native::CREDENTIAL_SIGNATURE_LENGTH);
        // TODO verify credential signature
    }

    #[test]
    fn sign_and_verify_test() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);

        // Now sign a message with no basename.
        let mut sig: Vec<u8> = vec![];
        let message = "hello".as_bytes().to_vec();
        ret = sign(&message, &cred, &sk, &None, true, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &None, &None, &sig, &message);
        assert_eq!(ret, true);
    }

    #[test]
    fn sign_and_verify_with_required_cred_test() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);

        // Now sign a message with no basename.
        let mut sig: Vec<u8> = vec![];
        let message = "hello".as_bytes().to_vec();
        let some_cred = Some(cred.clone());
        // To enforce a given credential, we can't randomize at sign.
        // (Or we collected the randomized cred first).
        ret = sign(&message, &cred, &sk, &None, false, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &None, &some_cred, &sig, &message);
        assert_eq!(ret, true);

        // Expect failure
        ret = sign(&message, &cred, &sk, &None, true, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &None, &some_cred, &sig, &message);
        assert_eq!(ret, false);
    }

    #[test]
    fn sign_and_verify_with_basename_test() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);

        // Now sign a message with no basename.
        let mut sig: Vec<u8> = vec![];
        let message = "hello".as_bytes().to_vec();
        let basename = Some("5pm on Friday".as_bytes().to_vec());
        ret = sign(&message, &cred, &sk, &basename, true, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &basename, &None, &sig, &message);
        assert_eq!(ret, true);
        ret = verify(&group_pk, &None, &None, &sig, &message);
        assert_eq!(ret, false);
    }

    #[test]
    fn sign_and_verify_with_required_cred_with_basename_test() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);

        // Now sign a message with no basename.
        let mut sig: Vec<u8> = vec![];
        let message = "hello".as_bytes().to_vec();
        let basename = Some("5pm on Friday".as_bytes().to_vec());
        let some_cred = Some(cred.clone());
        // To enforce a given credential, we can't randomize at sign.
        // (Or we collected the randomized cred first).
        ret = sign(&message, &cred, &sk, &basename, false, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &basename, &some_cred, &sig, &message);
        assert_eq!(ret, true);
        ret = verify(&group_pk, &None, &some_cred, &sig, &message);
        assert_eq!(ret, false);

        // Randomize and fail.
        ret = sign(&message, &cred, &sk, &basename, true, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &basename, &some_cred, &sig, &message);
        assert_eq!(ret, false);
    }

    #[test]
    fn randomize_credential_sign_and_verify() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);

        // Randomize the credential once.
        let mut r_cred = vec![];
        assert_eq!(randomize_credential(&cred, &mut r_cred), true);

        // Now sign a message with no basename with rnd crd
        let mut sig: Vec<u8> = vec![];
        let message = "hello".as_bytes().to_vec();
        let some_cred = Some(r_cred.clone());
        ret = sign(&message, &r_cred, &sk, &None, false, &mut sig);
        assert_eq!(ret, true);
        assert_ne!(sig.len(), 0);
        ret = verify(&group_pk, &None, &some_cred, &sig, &message);
        assert_eq!(ret, true);
    }

    #[test]
    fn issued_credential_in_group() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);
        assert_eq!(credential_in_group(&cred, &group_pk), true);

        // Generate a different group_pk and prove it isn't in the group
        let mut issuer2_sk = Vec::new();
        let mut group2_pk = Vec::new();
        assert_eq!(
            generate_issuer_keypair(&mut issuer2_sk, &mut group2_pk),
            true
        );
        assert_eq!(credential_in_group(&cred, &group2_pk), false);
    }

    #[test]
    fn randomize_credential_in_group() {
        // Setup group and member keys
        let mut issuer_sk = Vec::new();
        let mut group_pk = Vec::new();
        let mut ret = generate_issuer_keypair(&mut issuer_sk, &mut group_pk);
        assert_eq!(ret, true);
        let mut sk = Vec::new();
        let mut pk = Vec::new();
        let id = String::from("test-wallet-1").into_bytes().to_vec();
        ret = generate_wallet_keypair(&id, &mut sk, &mut pk);
        assert_eq!(ret, true);
        let mut cred = Vec::new();
        let mut cred_sig = Vec::new();
        ret = issue_credential(&pk, &issuer_sk, &id, &mut cred, &mut cred_sig);
        assert_eq!(ret, true);

        // Randomize the credential once.
        let mut r_cred = vec![];
        assert_eq!(randomize_credential(&cred, &mut r_cred), true);
        assert_eq!(credential_in_group(&r_cred, &group_pk), true);

        // Generate a different group_pk and prove it isn't in the group
        let mut issuer2_sk = Vec::new();
        let mut group2_pk = Vec::new();
        assert_eq!(
            generate_issuer_keypair(&mut issuer2_sk, &mut group2_pk),
            true
        );
        assert_eq!(credential_in_group(&r_cred, &group2_pk), false);
    }
}
