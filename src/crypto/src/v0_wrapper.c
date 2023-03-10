/*
 * Copyright 2023 The Briolette Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <ecdaa.h>

#include <string.h>

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/random.h>
#include <unistd.h>

#define logf(format, ...) fprintf (stderr, "%s:%d:%s:" format, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define check_ecdaa_buf(_name, _length) { \
        if (_name < _length()) { \
          logf(#_name " < " #_length ": (%zu < %zu)\n", \
                     _name, _length()); \
          return 2; \
        } \
      }

static void wrapper_rand(void *buf, size_t buflen)
{
    ssize_t read_ret = getrandom(buf, buflen, 0);
    if (read_ret == -1 || (size_t)read_ret != buflen) {
        logf("getrandom() failed. Ret=%zd, errno=%d\n", read_ret, errno);
        exit(1);
    }
}

int generate_wallet_keypair(uint8_t* secret_key, size_t secret_key_len,
                            uint8_t* public_key, size_t public_key_len,
                            uint8_t* nonce, size_t nonce_len) {
  struct ecdaa_member_public_key_FP256BN pk;
  struct ecdaa_member_secret_key_FP256BN sk;
  if (!public_key || public_key_len < ecdaa_member_public_key_FP256BN_length() ||
      !secret_key || secret_key_len < ecdaa_member_secret_key_FP256BN_length()) {
    logf("argument invariants violated (%p != 0, %zu < %zu, %p != 0, %zu < %zu)\n",
    secret_key, secret_key_len, ecdaa_member_secret_key_FP256BN_length(),
    public_key, public_key_len, ecdaa_member_public_key_FP256BN_length());
    return -2;
  }

  int ret = ecdaa_member_key_pair_FP256BN_generate(&pk, &sk, nonce, nonce_len, wrapper_rand);
  if (ret != 0) {
    logf("failed to generate wallet keypair: %d\n", ret);
    return ret;
  }
  ecdaa_member_public_key_FP256BN_serialize(public_key, &pk);
  ecdaa_member_secret_key_FP256BN_serialize(secret_key, &sk);
  return 0;
}

// We don't bother with the issuer public key since we only need a secret and group key.
int generate_issuer_keypair(uint8_t* issuer_secret_key, size_t issuer_secret_key_len,
                            uint8_t* group_public_key, size_t group_public_key_len) {
  if (!issuer_secret_key || issuer_secret_key_len < ecdaa_issuer_secret_key_FP256BN_length() ||
      !group_public_key || group_public_key_len < ecdaa_group_public_key_FP256BN_length()) {
    logf("argument invariants violated (%p != 0, %zu < %zu, %p != 0, %zu < %zu)\n",
    issuer_secret_key, issuer_secret_key_len, ecdaa_issuer_secret_key_FP256BN_length(),
    group_public_key, group_public_key_len, ecdaa_group_public_key_FP256BN_length());
    return -2;
  }
  struct ecdaa_issuer_public_key_FP256BN ipk;
  struct ecdaa_issuer_secret_key_FP256BN isk;
  int ret = ecdaa_issuer_key_pair_FP256BN_generate(&ipk, &isk, wrapper_rand);
  if (ret != 0) {
    logf("failed to generate an issuer keypair\n");
    return -1;
  }
  ecdaa_group_public_key_FP256BN_serialize(group_public_key, &ipk.gpk);
  ecdaa_issuer_secret_key_FP256BN_serialize(issuer_secret_key, &isk);
  return 0;
}


int issue_credential(uint8_t* member_public_key, size_t member_public_key_len,
                     uint8_t* issuer_secret_key, size_t issuer_secret_key_len,
                     uint8_t* credential_out, size_t credential_out_len,
                     uint8_t* credential_signature_out, size_t credential_signature_out_len,
                     uint8_t* nonce, size_t nonce_len)
{
    // Read member public key from disk.
    // NOTE: If this Join procedure is being done remotely,
    //  there should be some way of authenticating this member's public key.
    //  For our purposes, we assume this is an "in-factory" join,
    //  and so the authenticity of this member is ensured
    //  via physical means.
    
    if (member_public_key_len < ecdaa_member_public_key_FP256BN_length()) {
            logf("member_public_key_len < ecdaa_member_public_key_FP256BN_length: (%zu < %zu)", member_public_key_len, ecdaa_member_public_key_FP256BN_length());
            return -2;
    }
    if (issuer_secret_key_len < ecdaa_issuer_secret_key_FP256BN_length()) {
            logf("issuer_secret_key_len < ecdaa_issuer_secret_key_FP256BN_length: (%zu < %zu)", issuer_secret_key_len, ecdaa_issuer_secret_key_FP256BN_length());
            return -2;
    }
    if (credential_out_len < ecdaa_credential_FP256BN_length()) {
            logf("credential_out_len < ecdaa_credential_FP256BN_length: (%zu < %zu)", credential_out_len, ecdaa_credential_FP256BN_length());
            return -2;
    }
    if (credential_signature_out_len < ecdaa_credential_FP256BN_signature_length()) {
            logf("credential_signature_out_len < ecdaa_credential_FP256BN_signature_length: (%zu < %zu)", credential_signature_out_len, ecdaa_credential_FP256BN_signature_length());
            return -2;
    }


    struct ecdaa_member_public_key_FP256BN pk;
    int ret = ecdaa_member_public_key_FP256BN_deserialize(&pk, member_public_key, (uint8_t*)nonce, (uint32_t)nonce_len);
    if (0 != ret)
        return ret;

    struct ecdaa_issuer_secret_key_FP256BN isk;
    ret = ecdaa_issuer_secret_key_FP256BN_deserialize(&isk, issuer_secret_key);
    if (0 != ret)
        return ret;

    struct ecdaa_credential_FP256BN cred;
    struct ecdaa_credential_FP256BN_signature cred_sig;
    ret = ecdaa_credential_FP256BN_generate(&cred, &cred_sig, &isk, &pk, wrapper_rand);
    if (0 != ret) {
        return ret;
    }

    ecdaa_credential_FP256BN_serialize(credential_out, &cred);
    if (0 != ret) {
        return ret;
    }

    ecdaa_credential_FP256BN_signature_serialize(credential_signature_out, &cred_sig);
    if (0 != ret) {
        return ret;
    }

    return 0;
}

int randomize_credential(uint8_t* credential, size_t credential_len,
                         uint8_t* rand_cred, size_t rand_cred_len) {
    if (credential == NULL || credential_len == 0 || rand_cred == NULL || rand_cred_len == 0) {
        logf("NULL or empty arguments\n");
        return 2;
    }
    check_ecdaa_buf(credential_len, ecdaa_credential_FP256BN_length);
    check_ecdaa_buf(rand_cred_len, ecdaa_credential_FP256BN_length);
    struct ecdaa_credential_FP256BN cred;
    if (ecdaa_credential_FP256BN_deserialize(&cred, credential) != 0) {
        logf("error deserializing signing credential\n");
        return 2;
    }
    // Randomize the credential
    struct ecdaa_credential_FP256BN cred_out;
    int ret = ecdaa_credential_FP256BN_randomize(&cred, wrapper_rand, &cred_out);
    if (ret) {
      return ret;
    }
    ecdaa_credential_FP256BN_serialize(rand_cred, &cred_out);
    return 0;
}

// Returns 0 if in group.
int credential_in_group(uint8_t* credential, size_t credential_len,
                        uint8_t* group_public_key, size_t group_public_key_len) {
    if (credential == NULL || credential_len == 0 || group_public_key == NULL || group_public_key_len == 0) {
        logf("NULL or empty arguments\n");
        return 2;
    }
    check_ecdaa_buf(credential_len, ecdaa_credential_FP256BN_length);
    check_ecdaa_buf(group_public_key_len, ecdaa_group_public_key_FP256BN_length);

    struct ecdaa_credential_FP256BN cred;
    if (ecdaa_credential_FP256BN_deserialize(&cred, credential) != 0) {
        logf("error deserializing signing credential\n");
        return 2;
    }
    struct ecdaa_group_public_key_FP256BN gpk;
    if (ecdaa_group_public_key_FP256BN_deserialize(&gpk, group_public_key) != 0) {
        logf("could not parse the group key\n");
        return 1;
    }
    // Calling with a NULL cred sig bypasses the pk check.
    return ecdaa_credential_FP256BN_validate(&cred, NULL, NULL, &gpk);
}

// Creates a _member_ signature over the message.
// If basename is not NULL, it is used.
// If randomize_credential is non-zero, a classic ECDAA signature occurs.
// If randomize_credential is 0, the credential is used as supplied,
//    assuming it is pre-randomized.
int sign(uint8_t* message, size_t message_len,
         uint8_t* basename, size_t basename_len,
         uint8_t* credential, size_t credential_len,
         uint8_t* secret_key, size_t secret_key_len,
         int randomize_credential,
         uint8_t* out, size_t out_len) {

  if (message == NULL || message_len == 0 || credential == NULL || credential_len == 0 ||
      secret_key == NULL || secret_key_len == 0 ||
      (basename == NULL && basename_len > 0)
      ) {
    logf("NULL or empty arguments\n");
    return 2;
  }
  if (basename == NULL) {
    check_ecdaa_buf(out_len, ecdaa_signature_FP256BN_length);
  } else {
    check_ecdaa_buf(out_len, ecdaa_signature_FP256BN_with_nym_length);
  }
  check_ecdaa_buf(credential_len, ecdaa_credential_FP256BN_length);
  check_ecdaa_buf(secret_key_len, ecdaa_member_secret_key_FP256BN_length);

  struct ecdaa_member_secret_key_FP256BN sk;
  if (ecdaa_member_secret_key_FP256BN_deserialize(&sk, secret_key) != 0) {
      logf("error deserializing secret key\n");
      return 2;
  }
  struct ecdaa_credential_FP256BN cred;
  if (ecdaa_credential_FP256BN_deserialize(&cred, credential) != 0) {
      logf("error deserializing signing credential\n");
      return 2;
  }

  struct ecdaa_signature_FP256BN signature;
  int ret = 1;
  if (randomize_credential == 0) {
    ret = ecdaa_signature_FP256BN_sign_only(&signature, message, message_len, basename, basename_len, &sk, &cred, wrapper_rand);
  }  else {
    ret = ecdaa_signature_FP256BN_sign(&signature, message, message_len, basename, basename_len, &sk, &cred, wrapper_rand);
  }
  if (ret != 0) {
    logf("signing failed!");
    return 3;
  }
  // Return the signature.
  int has_nym = basename != NULL;
  ecdaa_signature_FP256BN_serialize(out, &signature, has_nym);
  return 0;
}

// Returns 0 if the signature is valid for the GPK and message.
// If a basename is supplied, verification will required it.
// If a req_signer_cred is supplied, the signature must use that credential.
//
// TODO: Add pseudonyn revocation list support.h
int verify_signature(uint8_t* signature, size_t signature_len,
                     uint8_t* message, size_t message_len,
                     uint8_t* group_public_key, size_t group_public_key_len,
                     uint8_t* req_signer_cred, size_t req_signer_cred_len,
                     uint8_t* basename, size_t basename_len) {
  if (signature == NULL || signature_len == 0 || message == NULL || message_len == 0 ||
      group_public_key == NULL || group_public_key_len == 0 ||
      (req_signer_cred == NULL && req_signer_cred_len > 0) ||
      (basename == NULL && basename_len > 0)
      ) {
    logf("NULL or empty arguments\n");
    return 2;
  }
  if (basename == NULL) {
    check_ecdaa_buf(signature_len, ecdaa_signature_FP256BN_length);
  } else {
    check_ecdaa_buf(signature_len, ecdaa_signature_FP256BN_with_nym_length);
  }
  check_ecdaa_buf(group_public_key_len, ecdaa_group_public_key_FP256BN_length);

  int has_nym = (basename != NULL);
  struct ecdaa_signature_FP256BN sig;
  if (ecdaa_signature_FP256BN_deserialize(&sig, signature, has_nym) != 0) {
      logf("error deserializing signature\n");
      return 1;
  }
  struct ecdaa_group_public_key_FP256BN gpk;
  if (ecdaa_group_public_key_FP256BN_deserialize(&gpk, group_public_key) != 0) {
      logf("could not parse the group key\n");
      return 1;
  }
  // If there is a required signing cred, ensure it matches the cred on the signature.
  if (req_signer_cred) {
      check_ecdaa_buf(req_signer_cred_len, ecdaa_credential_FP256BN_length);
      struct ecdaa_credential_FP256BN sig_cred;
      if (ecdaa_credential_FP256BN_deserialize(&sig_cred, req_signer_cred) != 0) {
          logf("error deserializing required signer credential\n");
          return 1;
      }

      if (ecdaa_signature_FP256BN_credential(&sig, &sig_cred) != 0) {
          //logf("required credential doesn't match signature credential!\n");
          return 1;
      }
  }

  // TODO: support injection for pseudonym catching!
  struct ecdaa_revocations_FP256BN revocations;
  revocations.sk_list = NULL;
  revocations.sk_length = 0;
  // This is signature->K from the revoked sigs, in an array.
  revocations.bsn_list = NULL;
  revocations.bsn_length = 0;

  return ecdaa_signature_FP256BN_verify(&sig, &gpk, &revocations, message, message_len,
                                     basename, basename_len);
}
