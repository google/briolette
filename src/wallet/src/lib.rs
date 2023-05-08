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
use briolette_proto::briolette::clerk::clerk_client::ClerkClient;
use briolette_proto::briolette::clerk::{
    EpochRequest, EpochUpdate, EpochVerify, GetTicketsRequest, TicketRequest, TicketRequests,
};
use briolette_proto::briolette::mint::mint_client::MintClient;
use briolette_proto::briolette::mint::GetTokensRequest;
use briolette_proto::briolette::registrar::registrar_client::RegistrarClient;
use briolette_proto::briolette::registrar::{
    Algorithm, CredentialRequest, HardwareId, RegisterRequest, SecurityLevel,
    Signature as RegistrarSignature,
};
use briolette_proto::briolette::token;
use briolette_proto::briolette::token::TokenTransfer;
use briolette_proto::briolette::token::TokenVerify;
use briolette_proto::briolette::validate::validate_client::ValidateClient;
use briolette_proto::briolette::validate::ValidateTokensRequest;
use briolette_proto::briolette::Version;
use briolette_proto::vec_utils;
use chrono::Utc;

use log::*;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    PublicKey,
};
use rand::Rng;
use sha2::{Digest, Sha256};

use async_trait::async_trait;
use prost::Message;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::convert::From;
use std::path::Path;

// This is prototype code so we are going full async. As seen in the testing,
// much of the logic is synchronous. Later, we'll come back through and extract
// the business logic such that async can be optional based on the Wallet
// implementation.
#[async_trait]
pub trait Wallet: Clone + Serialize + DeserializeOwned + Send {
    /// Generates a public/private keypair.
    fn initialize_keys(&mut self, hw_id: &[u8]) -> bool;
    /// Acquires a credential for the public key from the issuer which is
    /// underlying impl specific.
    /// Returns true on success.
    /// Returns false on failure or if |initialize_keys| has not been called.
    async fn initialize_credential(&mut self) -> bool;
    /// Retrieve the latest epoch data
    async fn synchronize(&mut self) -> bool;
    fn gossip_synchronize(&mut self, epoch_update: &EpochUpdate) -> bool;
    // get_tickets refills the stored transaction tickets.
    // It does so by generating randomized credentials and getting them
    // signed by the ticket authority.
    async fn get_tickets(&mut self, count: u32) -> bool;
    // Verifies a ticket received from the server or provided by a peer against the stored
    // ticket authority. A ticket is an encoded randomized credential and a credential signature.
    // This is trivial on token::TicketVerify trait.
    // fn verify_ticket(&self, timestamp: u64, ticket: &Vec<u8>) -> bool;

    // This verifies unheld tokens, not in-wallet tokens which are always verified.
    // TODO: Add a validation helper.
    // TODO: Move the Receiver proto handling in here.
    fn verify_tokens(&self, tokens: &Vec<token::Token>) -> bool;

    // "Withdraws" money from the mint.
    async fn withdraw(&mut self, amount: u32) -> bool;

    // Presently this method will transfer |amount| tokens to
    // |recipient| and then hold them for tranmission.
    // |recipient| is a serialized SignedTicket.
    fn transfer(&mut self, amount: u32, recipient: Vec<u8>) -> bool;

    // Validate currently held tokens. Later this will enable recovery, but for
    // now it assures they are legitimate.
    async fn validate(&self) -> bool;
    // Validates tokens which are not held.
    async fn validate_tokens(&self, tokens: &Vec<token::Token>) -> bool;
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Credential {
    issuer_uri: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    group_public_key: Option<Vec<u8>>,
    credential: Option<Vec<u8>>,
    // Issuing cred signature.
    credential_signature: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Epoch {
    #[serde(skip)]
    pub epoch_update: Option<EpochUpdate>,
    eu_serialized: Vec<u8>,
    pub epoch: u64,
    group_bitfield: Vec<u8>,
    ttc_group_public_keys: Vec<Vec<u8>>,
    epoch_signing_keys: Vec<Vec<u8>>,
    ticket_signing_keys: Vec<Vec<u8>>,
    mint_signing_keys: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct WalletData {
    id: Vec<u8>,
    hw_id: Vec<u8>,
    // Network Access Credential
    // Allows interaction with network services.
    // The issuer reflects the vendor group the wallet is in.
    // This credential allows the server to enforce singular limits without long-term linkability
    // as well as enforce "hardware" specific policies, such as ticket expirations.
    // The ticket issuance server will expect a request signed by this credential (randomized) over
    // a list of randomized transfer credentials to enable group association and revocability
    // while supporting transactional privacy. (E.g., the operator may be able to tell if A->B is a
    // self-transfer, but no other entities will know. Additionally, if the operator allows
    // overlapping ticket expiration, then even then it will only know if the transfer was to the
    // same hw family)
    // (N.b., ticket expirations provide a means for currency recovery if a wallet is lost.)
    network_credential: Credential,
    // Token Transfer Credential
    // Allows exchange of currency.
    // The issuer reflects only the timing of issuance.
    // (e.g., most operators will have at least two issuers active to enable rotations.)
    transfer_credential: Credential,
    // Ticket server URI e.g., "http://[::1]:50052"
    clerk_uri: String,
    // Ticket server URI e.g., "http://[::1]:50053"
    mint_uri: String,
    // Validate server URI e.g., "http://[::1]:50055"
    validate_uri: String,
    // Epoch data
    pub epoch: Epoch,
    // Tickets
    pub tickets: Vec<TicketEntry>,
    // Tokens
    // TODO: create proper accessors
    pub tokens: Vec<TokenEntry>,
    // Tokens ready to be sent
    pub pending_tokens: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct TicketEntry {
    ticket: Vec<u8>,
    credential: Vec<u8>,
    group_number: u32,
    created_on: u64,
    lifetime: u32,
    signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct TokenEntry {
    pub token: Vec<u8>, // most minimal Token.
    credential: Vec<u8>,
    whole_value: i32,
    fractional_value: f32,
    value_code: i32,
    // TODO add mint pk to demo different token authority for same value code.
}

impl From<token::Token> for TokenEntry {
    fn from(item: token::Token) -> Self {
        let history: &token::History;
        if item.history.len() == 0 {
            // Grab from token base
            history = item.base.as_ref().unwrap();
        } else {
            history = item.history.last().unwrap();
        }
        let credential: Vec<u8> = history
            .transfer
            .as_ref()
            .unwrap()
            .recipient
            .as_ref()
            .unwrap()
            .ticket
            .as_ref()
            .unwrap()
            .credential
            .clone();
        Self {
            token: item.encode_to_vec(),
            credential,
            whole_value: item
                .descriptor
                .as_ref()
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .whole,
            fractional_value: item
                .descriptor
                .as_ref()
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .fractional,
            value_code: item
                .descriptor
                .as_ref()
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .code,
        }
    }
}

impl From<TicketEntry> for token::SignedTicket {
    fn from(item: TicketEntry) -> Self {
        Self {
            ticket: Some(token::Ticket {
                credential: item.credential,
                tags: Some(token::TicketData {
                    group_number: item.group_number,
                    lifetime: item.lifetime,
                    created_on: item.created_on,
                }),
            }),
            signature: item.signature,
        }
    }
}

impl From<TokenEntry> for token::Token {
    fn from(item: TokenEntry) -> Self {
      token::Token::decode(item.token.as_slice()).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WalletDataError<'a>(&'a str);

impl WalletData {
    pub fn new(
        issuer_uri: String,
        clerk_uri: String,
        mint_uri: String,
        validate_uri: String,
    ) -> Self {
        WalletData {
            clerk_uri,
            mint_uri,
            validate_uri,
            network_credential: Credential {
                issuer_uri: issuer_uri.clone(),
                ..Default::default()
            },
            transfer_credential: Credential {
                issuer_uri,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn load(wallet_file: &Path) -> Result<Self, WalletDataError> {
        let maybe_data = std::fs::read(wallet_file);
        if let Ok(data) = maybe_data {
            let result = serde_json::from_slice(&data);
            if let Ok(wallet) = result {
                Ok(wallet)
            } else {
                Err(WalletDataError("cannot parse file"))
            }
        } else {
            Err(WalletDataError("cannot load from file"))
        }
    }

    pub fn store(&self, wallet_file: &Path) -> bool {
        let serialized = serde_json::to_vec(&self);
        if let Ok(data) = serialized {
            let res = std::fs::write(wallet_file, &data);
            if let Err(_err) = res {
                return false;
            }
            return true;
        }
        return false;
    }
}

#[async_trait]
impl Wallet for WalletData {
    fn initialize_keys(&mut self, id: &[u8]) -> bool {
        self.id = Vec::from(id);
        self.hw_id = digest(id).into_bytes();
        let mut ret = v0::generate_wallet_keypair(
            &self.hw_id,
            &mut self.transfer_credential.secret_key,
            &mut self.transfer_credential.public_key,
        );
        if ret == false {
            return ret;
        }
        ret = v0::generate_wallet_keypair(
            &self.transfer_credential.public_key,
            &mut self.network_credential.secret_key,
            &mut self.network_credential.public_key,
        );
        return ret;
    }

    async fn initialize_credential(&mut self) -> bool {
        if self.transfer_credential.issuer_uri.len() == 0
            || self.network_credential.issuer_uri.len() == 0
        {
            eprintln!("issuer_uri must be set before calling initialize_credential");
            return false;
        }
        if self.transfer_credential.secret_key.len() == 0
            || self.network_credential.secret_key.len() == 0
        {
            eprintln!("initialize_keys() must be called before initialize_credential");
            return false;
        }
        let request = tonic::Request::new(RegisterRequest {
            version: Version::Current.into(),
            hwid: Some(HardwareId {
                vendor_id: 1,
                software_id: 0,
                hardware_id: 1,
                hw_id: self.hw_id.clone(),
                security: SecurityLevel::Low.into(),
            }),
            hwid_signature: Some(RegistrarSignature {
                algorithm: Algorithm::None.into(),
                signature: vec![],
                public_key: vec![],
            }),
            network_credential: Some(CredentialRequest {
                public_key: self.network_credential.public_key.clone(),
            }),
            transfer_credential: Some(CredentialRequest {
                public_key: self.transfer_credential.public_key.clone(),
            }),
        });
        match RegistrarClient::connect(self.network_credential.issuer_uri.clone()).await {
            Ok(mut client) => {
                let response = client.register_call(request).await;
                //println!("RESPONSE={:?}", response);
                let msg;
                match response {
                    Ok(reply) => msg = reply.into_inner(),
                    Err(_) => return false,
                }
                if let Some(cred) = msg.network_credential {
                    self.network_credential.credential = Some(cred.credential);
                    self.network_credential.credential_signature = Some(cred.credential_signature);
                    self.network_credential.group_public_key = Some(cred.group_public_key);
                }
                if let Some(cred) = msg.transfer_credential {
                    self.transfer_credential.credential = Some(cred.credential);
                    self.transfer_credential.credential_signature = Some(cred.credential_signature);
                    self.transfer_credential.group_public_key = Some(cred.group_public_key);
                }
                return true;
            }
            Err(e) => {
                eprintln!("could not connect to registrar: {:?}", e);
            }
        }
        return false;
    }

    async fn get_tickets(&mut self, count: u32) -> bool {
        if self.transfer_credential.credential.is_none()
            || self.network_credential.credential.is_none()
        {
            eprintln!("wallet must have valid credentials first.");
            return false;
        }
        let mut requests = TicketRequests::default();
        for _i in 0..count {
            let mut credential = vec![];
            assert!(
                v0::randomize_credential(
                    &self.transfer_credential.credential.clone().unwrap(),
                    &mut credential
                ),
                "failed to randomize the wallet ttc credential!"
            );
            // Group count
            let max_groups = self.epoch.group_bitfield.len() * 8;
            // TODO: Inject to seedable.
            let mut rng = rand::thread_rng();
            let group_number: u32 = rng.gen_range(0..max_groups) as u32;
            let tr = TicketRequest {
                credential,
                group_number,
            };
            requests.request.push(tr);
        }
        // Serialize the request list and sign with the NAC, using the current epoch as the basename.
        let requests_serialized = requests.encode_to_vec();
        let basename = Some(self.epoch.epoch.to_le_bytes().to_vec());
        let mut signature = vec![];
        assert!(v0::sign(
            &requests_serialized,
            &self.network_credential.credential.clone().unwrap(),
            &self.network_credential.secret_key,
            &basename,
            true,
            &mut signature
        ));

        let request = GetTicketsRequest {
            version: Version::Current.into(),
            known_epoch: self.epoch.epoch,
            nac_public_key: self.network_credential.group_public_key.clone().unwrap(),
            ttc_public_key: self.transfer_credential.group_public_key.clone().unwrap(),
            requests: Some(requests),
            nac_signature: signature,
        };
        if let Ok(mut client) = ClerkClient::connect(self.clerk_uri.clone()).await {
            match client.get_tickets(request).await {
                Ok(response) => {
                    println!("get_tickets response={:?}", response);
                    let msg = response.into_inner();
                    // Ensure that the signing key is known.
                    let mut vk: Option<Vec<u8>> = None;
                    for key in &self.epoch.ticket_signing_keys {
                        if vec_utils::vec_equal(key, &msg.signing_key) {
                            vk = Some(key.clone());
                        }
                    }
                    if vk.is_none() {
                        eprintln!("Clerk presented unknown ticket signing key.");
                        return false;
                    }
                    let ticket_pk: PublicKey =
                        PublicKey::from_public_key_der(vk.unwrap().as_slice()).unwrap();
                    let ticket_vk: VerifyingKey = ticket_pk.into();

                    // Validate and add each signature
                    for signed_ticket in &msg.tickets {
                        let mut sig = signed_ticket.signature.clone();
                        sig.pop(); // Drop the RecId for now.

                        if let Some(ticket) = signed_ticket.ticket.clone() {
                            // Verify the ticket signature
                            let serialized = ticket.encode_to_vec();
                            match Signature::try_from(sig.as_slice()) {
                                Ok(signature) => {
                                    // Confirm signature over data
                                    match ticket_vk.verify(serialized.as_slice(), &signature) {
                                        Err(e) => {
                                            eprintln!("failed to verify signed ticket: {:?}", e);
                                            return false;
                                        }
                                        _ => {}
                                    }
                                }
                                Err(e) => {
                                    eprintln!("ticket signature field is invalid: {:?}", e);
                                    return false;
                                }
                            }
                            // Ticket is valid
                            let mut entry = TicketEntry::default();
                            entry.ticket = serialized;
                            entry.credential = ticket.credential.clone();
                            if let Some(tags) = ticket.tags {
                                entry.group_number = tags.group_number;
                                entry.created_on = tags.created_on;
                                entry.lifetime = tags.lifetime;
                            }
                            entry.signature = signed_ticket.signature.clone();
                            // Import the ticket!
                            self.tickets.push(entry);
                        }
                    }
                    return true;
                }
                Err(e) => {
                    eprintln!("get_tickets() failed: {:?}", e);
                    return false;
                }
            }
        }
        return false;
    }

    fn verify_tokens(&self, tokens: &Vec<token::Token>) -> bool {
        for token in tokens.iter() {
            if let Err(e) = token.verify(
                self.transfer_credential.group_public_key.as_ref().unwrap(),
                &self.epoch.mint_signing_keys,
                &self.epoch.ticket_signing_keys,
            ) {
                error!("invalid token: {:?}", e);
                return false;
            }
        }
        // TODO: Pulled validate out to simplify handling of the
        //       wallet data in receiver. These structures all need to
        //       be cleaned up.
        return true;
    }
    fn gossip_synchronize(&mut self, update: &EpochUpdate) -> bool {
        // TODO: Move this to a separate function for gossip updates
        // Verify the signature before accepting the data.
        let mut vk: Option<Vec<u8>> = None;
        for key in &self.epoch.epoch_signing_keys {
            if vec_utils::vec_equal(key, &update.signing_key) {
                vk = Some(key.clone());
            }
        }
        // TODO: We trust the first epoch signing keys we fetch.
        if vk == None && self.epoch.epoch_signing_keys.len() == 0 {
            vk = Some(update.signing_key.clone());
        }
        if let Some(signing_key) = vk {
            if let Err(code) = update.verify(&signing_key) {
                eprintln!("epoch update did not verify: {:?}", code);
                return false;
            }
        } else {
            eprintln!("could not verify epoch update -- no valid signing key found!");
            return false;
        }
        self.epoch.epoch_update = Some(update.clone());
        self.epoch.eu_serialized = update.encode_to_vec();
        if update.extended_data.is_none() {
            eprintln!("extended data is missing!");
            return false;
        }
        if let Some(data) = update.data.as_ref() {
            self.epoch.epoch = data.epoch;
            self.epoch.group_bitfield = data.group_bitfield.clone();
            // Before we continue, confirm the extended hash is legitimate.
            let eed_hash =
                Sha256::digest(update.extended_data.clone().unwrap().encode_to_vec()).to_vec();
            if vec_utils::vec_equal(&eed_hash, &data.extended_epoch_data_hash) == false {
                eprintln!("Extended data hash mismatched.");
                self.epoch.epoch_update = None;
                self.epoch.eu_serialized.clear();
                return false;
            }
        }
        if let Some(extended) = update.extended_data.as_ref() {
            // TODO: Unify naming of *signing keys
            self.epoch.ttc_group_public_keys = extended.ttc_group_public_keys.clone();
            self.epoch.epoch_signing_keys = extended.epoch_signing_keys.clone();
            self.epoch.ticket_signing_keys = extended.ticket_signing_keys.clone();
            self.epoch.mint_signing_keys = extended.mint_signing_keys.clone();
        }
        return true;
    }

    async fn synchronize(&mut self) -> bool {
        let request = tonic::Request::new(EpochRequest {
            version: Version::Current.into(),
            known_epoch: self.epoch.epoch,
        });
        match ClerkClient::connect(self.clerk_uri.clone()).await {
            Ok(mut client) => {
                let response = client.get_epoch(request).await;
                //println!("get_epoch response={:?}", response);
                let msg;
                match response {
                    Ok(reply) => msg = reply.into_inner(),
                    Err(e) => {
                        eprintln!("clerk server errored on epoch request: {:?}", e);
                        return false;
                    }
                }
                if let Some(update) = msg.update {
                    return self.gossip_synchronize(&update);
                }
            }
            Err(e) => {
                eprintln!("failed to connect fetch an epoch update: {:?}", e);
            }
        }
        return false;
    }

    async fn withdraw(&mut self, amount: u32) -> bool {
        if self.tickets.len() == 0 {
            eprintln!("out of tickets!");
            return false;
        }
        let ticket = self.tickets.pop().unwrap();
        let request = tonic::Request::new(GetTokensRequest {
            version: Version::Current.into(),
            amount: Some(token::Amount {
                whole: 1,
                fractional: 0.0,
                code: token::AmountType::TestToken.into(),
            }),
            tags: vec![token::Tag {
                value: Some(token::tag::Value::ValidUntil(
                    (86400 * 365) + Utc::now().timestamp() as u64,
                )),
            }],
            count: amount,
            ticket: Some(ticket.clone().into()),
        });

        match MintClient::connect(self.mint_uri.clone()).await {
            Ok(mut client) => {
                let response = client.get_tokens(request).await;
                //println!("get_epoch response={:?}", response);
                let msg;
                match response {
                    Ok(reply) => msg = reply.into_inner(),
                    Err(e) => {
                        eprintln!("mint server errored on get tokens request: {:?}", e);
                        return false;
                    }
                }
                for token in &mut msg.tokens.clone() {
                    // TODO: Verify!
                    self.tokens.push(token.clone().into());
                }
                return true;
            }
            Err(e) => {
                eprintln!("failed to connect fetch tokens: {:?}", e);
            }
        }
        // Keep the ticket if we failed to withdraw with it.
        self.tickets.push(ticket);
        return false;
    }

    fn transfer(&mut self, amount: u32, recipient: Vec<u8>) -> bool {
        if self.tokens.len() < amount as usize {
            warn!("transfer() called with insufficient tokens");
            return false;
        }
        if let Ok(signed_ticket) = token::SignedTicket::decode(recipient.as_slice()) {
            let mut tx_amt = amount;
            while let Some(token_entry) = self.tokens.pop() {
                if tx_amt == 0 {
                    break;
                }
                tx_amt -= 1;
                if let Ok(mut token) = token::Token::decode(token_entry.token.as_slice()) {
                    if let Err(e) =
                        token.transfer(&signed_ticket, self.transfer_credential.secret_key.clone())
                    {
                        error!("transfer() failed to sign token transfer: {:?}", e);
                        return false;
                    }
                    trace!("token transfer complete: {:?}", token.clone());
                    self.pending_tokens.push(token.encode_to_vec());
                } else {
                    error!(
                        "failed to decode internally stored token: {:?}",
                        token_entry.clone()
                    );
                    return false;
                }
            }
        }
        return true;
    }

    async fn validate_tokens(&self, tokens: &Vec<token::Token>) -> bool {
        if tokens.len() == 0 {
            error!("No tokens to validate");
            return false;
        }
        let request = tonic::Request::new(ValidateTokensRequest {
            version: Version::Current.into(),
            tokens: tokens.clone(),
        });

        match ValidateClient::connect(self.validate_uri.clone()).await {
            Ok(mut client) => {
                let response = client.validate_tokens(request).await;
                trace!("validate response = {:?}", response);
                let msg;
                match response {
                    Ok(reply) => msg = reply.into_inner(),
                    Err(e) => {
                        eprintln!("validate server errored on request: {:?}", e);
                        return false;
                    }
                }
                for (idx, ok) in msg.ok.iter().enumerate() {
                    if *ok == false {
                        // TODO: decide what to do with the information.
                        error!("token {} is bad!", idx);
                        return false;
                    }
                }
                return true;
            }
            Err(e) => {
                eprintln!("failed to connect to validate tokens: {:?}", e);
            }
        }
        return false;
    }

    async fn validate(&self) -> bool {
        if self.tokens.len() == 0 {
            error!("No tokens to validate");
            return false;
        }
        let tokens: Vec<token::Token> = self.tokens.iter().map(|t| token::Token::decode(t.token.as_slice()).unwrap()).collect();
        return self.validate_tokens(&tokens).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briolette_mint::server::BrioletteMint;
    use briolette_proto::briolette::clerk::clerk_server::ClerkServer;
    use briolette_proto::briolette::mint::mint_server::MintServer;
    use briolette_proto::briolette::registrar::registrar_server::RegistrarServer;
    use briolette_proto::briolette::tokenmap::token_map_server::TokenMapServer;
    use briolette_proto::briolette::validate::validate_server::ValidateServer;
    use briolette_proto::briolette::ErrorCode as BrioletteErrorCode;
    use briolette_tokenmap::server::BrioletteTokenMap;
    use briolette_validate::server::BrioletteValidate;
    use briolette_clerk::server::BrioletteClerk;
    use briolette_registrar::server::BrioletteRegistrar;
    use glob::glob;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    static TOKENMAP_RUNNING: AtomicUsize = AtomicUsize::new(0);

    #[test]
    pub fn setup_logger() {
        stderrlog::new()
            .quiet(false)
            .verbosity(1)
            .timestamp(stderrlog::Timestamp::Millisecond)
            .init()
            .unwrap();
    }

    #[test]
    pub fn load_missing() {
        let wp = Path::new("bogus.test.file");
        std::fs::remove_file(&wp).unwrap_or(());
        let wd = WalletData::load(&wp);
        assert_eq!(wd, Err(WalletDataError("cannot load from file")));
    }

    #[test]
    pub fn load_unparseable() {
        let wp = Path::new("wallet.test.unparseable");
        std::fs::remove_file(&wp).unwrap_or(());
        std::fs::write(&wp, b"nonsense").expect("writing nonsense failed");
        let wd = WalletData::load(&wp);
        assert_eq!(wd, Err(WalletDataError("cannot parse file")));
        std::fs::remove_file(&wp).unwrap();
    }

    #[test]
    pub fn store_load() {
        let wp = Path::new("wallet.test.store_load");
        std::fs::remove_file(&wp).unwrap_or(());
        let mut wd = WalletData::default();
        wd.id = vec![1, 2, 3];
        assert_eq!(wd.store(&wp), true);
        let wd2 = WalletData::load(&wp).unwrap();
        assert_eq!(wd.id, wd2.id);
        std::fs::remove_file(&wp).unwrap();
    }

    #[test]
    pub fn initialize_keys_basic() {
        let mut wd = WalletData::default();
        assert_eq!(wd.initialize_keys(b"test-id"), true);
    } //tokio::test(flavor = "multi_thread")]

    async fn setup_tokenmap() -> String {
        let db_id = TOKENMAP_RUNNING.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel::<u16>();

        tokio::spawn(async move {
            println!("Launching test tokenmap...");
            let listener = TcpListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr.port()).unwrap();

            let dbfile = format!("tokenmap.{}.db", db_id).to_string();
            let tokenmap = BrioletteTokenMap::new(&dbfile).await.unwrap();

            match tonic::transport::Server::builder()
                .add_service(TokenMapServer::new(tokenmap))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
            {
                Ok(_) => {
                    eprintln!("tokenmap server started");
                    // TODO: can we put file clean up here and use Drop to signal shutdown?
                }
                Err(x) => {
                    eprintln!("tokenmap server failed to start: {:?}", x);
                }
            }
        });
        match rx.await {
            Ok(v) => return format!("http://[::1]:{}", v),
            Err(_) => println!("didn't receive the port"),
        }
        assert!(false);
        return "".to_string();
    }

    async fn setup_registrar(_tokenmap_uri: String) -> String {
        // Setup a registrar server
        let (tx, rx) = oneshot::channel::<u16>();
        tokio::spawn(async move {
            println!("Launching test registrar...");
            // THese are generated by registrar binaries.
            let nsk = Path::new("../registrar/data/net_issuer.sk");
            let ngpk = Path::new("../registrar/data/net_issuer.gpk");
            let tsk = Path::new("../registrar/data/ttc_issuer.sk");
            let tgpk = Path::new("../registrar/data/ttc_issuer.gpk");
            let registrar = BrioletteRegistrar::new(nsk, ngpk, tsk, tgpk);
            let listener = TcpListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr.port()).unwrap();

            match tonic::transport::Server::builder()
                .add_service(RegistrarServer::new(registrar))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
            {
                Ok(_) => {
                    eprintln!("registar server started");
                }
                Err(x) => {
                    eprintln!("registrar server failed to start: {:?}", x);
                }
            }
        });
        match rx.await {
            Ok(v) => return format!("http://[::1]:{}", v),
            Err(_) => println!("didn't receive the port"),
        }
        assert!(false);
        return "".to_string();
    }

    async fn setup_clerk(tokenmap_uri: String) -> String {
        // Setup a clerk server
        let (tx, rx) = oneshot::channel::<u16>();
        tokio::spawn(async move {
            println!("Launching test clerk...");
            println!("Ensure briolette-clerk-server has generated clerk.state before running.");
            // The ette-clerk-server must be called with registrar data above.
            let mut clerk = BrioletteClerk::load(Path::new("../clerk/data/clerk.state")).unwrap();
            clerk.tokenmap_uri = tokenmap_uri;
            let listener = TcpListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr.port()).unwrap();

            match tonic::transport::Server::builder()
                .add_service(ClerkServer::new(clerk))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
            {
                Ok(_) => {
                    eprintln!("clerk server started");
                }
                Err(x) => {
                    eprintln!("clerk server failed to start: {:?}", x);
                }
            }
        });
        match rx.await {
            Ok(v) => return format!("http://[::1]:{}", v),
            Err(_) => println!("didn't receive the port"),
        }
        assert!(false);
        return "".to_string();
    }

    async fn setup_mint(tokenmap_uri: String) -> String {
        // Setup a registrar server
        let (tx, rx) = oneshot::channel::<u16>();
        tokio::spawn(async move {
            println!("Launching test registrar...");
            // These are generated by mint server binaries.
            let msk = std::fs::read(Path::new("../mint/data/mint.sk"))
                .expect("mint/data/mint.sk not populated yet");
            let ttc_gpk = std::fs::read("../registrar/data/wallet.ttc.gpk")
                .expect("registrar/data/wallet.ttc.gpk not populated yet");
            let ticket_pk =
                std::fs::read("../clerk/data/ticket.pk").expect("clerk/data not populated yet");
            let mint = BrioletteMint::new(msk, ttc_gpk, vec![ticket_pk], tokenmap_uri.to_string())
                .unwrap();
            let listener = TcpListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr.port()).unwrap();

            // serve_with_shutdown and a oneshot works in theory, it doesn't
            // release the port in a useful timeframe. Need to move over to
            // serve_with_incoming()
            match tonic::transport::Server::builder()
                .add_service(MintServer::new(mint))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
            {
                Ok(_) => {
                    eprintln!("registar server started");
                }
                Err(x) => {
                    eprintln!("registrar server failed to start: {:?}", x);
                }
            }
        });
        match rx.await {
            Ok(v) => return format!("http://[::1]:{}", v),
            Err(_) => println!("didn't receive the port"),
        }
        assert!(false);
        return "".to_string();
    }

    async fn setup_validate(clerk_uri: String, tokenmap_uri: String) -> String {
        // Setup a validate server
        let (tx, rx) = oneshot::channel::<u16>();
        tokio::spawn(async move {
            println!("Launching test validate...");
            // These are generated by validate server binaries.
            let epoch_pk =
                std::fs::read("../clerk/data/epoch.pk").expect("clerk/data not populated yet");
            let validate = BrioletteValidate::new(clerk_uri, tokenmap_uri, epoch_pk)
                .await
                .unwrap();
            let listener = TcpListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr.port()).unwrap();

            // serve_with_shutdown and a oneshot works in theory, it doesn't
            // release the port in a useful timeframe. Need to move over to
            // serve_with_incoming()
            match tonic::transport::Server::builder()
                .add_service(ValidateServer::new(validate))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
            {
                Ok(_) => {
                    eprintln!("registar server started");
                }
                Err(x) => {
                    eprintln!("registrar server failed to start: {:?}", x);
                }
            }
        });
        match rx.await {
            Ok(v) => return format!("http://[::1]:{}", v),
            Err(_) => println!("didn't receive the port"),
        }
        assert!(false);
        return "".to_string();
    }

    #[tokio::test]
    async fn initialize_credential_basic() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        assert_eq!(wd.initialize_keys(b"test-id"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_ne!(wd.network_credential.credential, None);
        assert_ne!(wd.transfer_credential.credential, None);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_epoch_from_clerk() {
        // FIXME: This test depends on clerk having a valid EpochUpdate in data/clerk.state.
        let tokenmap_uri = setup_tokenmap().await;
        let mut wd = WalletData::default();
        wd.clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        assert_eq!(wd.synchronize().await, true);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_tickets_ok() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_ok() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        wd.mint_uri = mint_uri.clone();
        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        assert_eq!(wd.withdraw(10).await, true);
        assert_eq!(wd.tokens.len(), 10);
        assert_eq!(wd.tickets.len(), 4);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_tickets_norecovery() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        wd.mint_uri = mint_uri.clone();

        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        // Drop the recovery byte.
        wd.tickets[4].signature.pop();
        assert_eq!(wd.withdraw(10).await, false);
        assert_eq!(wd.tokens.len(), 0);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_tickets_local_modification() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        wd.mint_uri = mint_uri.clone();

        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        // Cause signature failure.
        wd.tickets[4].group_number = 41414141;
        assert_eq!(wd.withdraw(10).await, false);
        assert_eq!(wd.tokens.len(), 0);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_tickets_corrupt_sig() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        wd.mint_uri = mint_uri.clone();

        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        // Cause signature failure.
        wd.tickets[4].signature[1] = 0;
        wd.tickets[4].signature[2] = 0;
        wd.tickets[4].signature[3] = 0;
        assert_eq!(wd.withdraw(10).await, false);
        assert_eq!(wd.tokens.len(), 0);
        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_and_transfer() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        wd.mint_uri = mint_uri.clone();
        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        assert_eq!(wd.withdraw(10).await, true);
        assert_eq!(wd.tokens.len(), 10);
        assert_eq!(wd.tickets.len(), 4);
        // Not popping so we can easily reuse it.
        let destination: token::SignedTicket = wd.tickets.last().unwrap().clone().into();
        let destination_addr = destination.encode_to_vec();
        assert_eq!(wd.transfer(2, destination_addr), true);
        assert_eq!(wd.pending_tokens.len(), 2);
        let t = token::Token::decode(wd.pending_tokens[0].as_slice()).unwrap();
        // A token with a token base and transfer is 987 bytes.
        assert_eq!(wd.pending_tokens[0].len(), 987);
        assert_eq!(
            Ok(true),
            t.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // TODO: need validate server now!

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_and_transfer_and_transfer() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let mut wd = WalletData::default();
        wd.clerk_uri = clerk_uri.clone();
        wd.network_credential.issuer_uri = registrar_uri.clone();
        wd.transfer_credential.issuer_uri = registrar_uri.clone();
        wd.mint_uri = mint_uri.clone();
        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        assert_eq!(wd.withdraw(10).await, true);
        assert_eq!(wd.tokens.len(), 10);
        assert_eq!(wd.tickets.len(), 4);
        // Not popping so we can easily reuse it.
        let destination: token::SignedTicket = wd.tickets.last().unwrap().clone().into();
        let destination_addr = destination.encode_to_vec();
        assert_eq!(wd.transfer(2, destination_addr), true);
        assert_eq!(wd.pending_tokens.len(), 2);
        let t = token::Token::decode(wd.pending_tokens.pop().unwrap().as_slice()).unwrap();
        wd.tokens.push(t.into());
        // Transfer that token again!
        let next_dest: token::SignedTicket = wd.tickets[1].clone().into();
        assert_eq!(wd.transfer(1, next_dest.encode_to_vec()), true);
        // A token with a token base and transfer is 987 bytes + the second transfer.
        assert_ne!(wd.pending_tokens.last().unwrap().len(), 987);
        let mut t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        assert_eq!(
            Ok(true),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // change bits in the second history
        t2.history[1].signature[2] = t2.history[1].signature[2] + 1;
        t2.history[1].signature[3] = t2.history[1].signature[3] + 1;
        assert_eq!(
            Err(BrioletteErrorCode::InvalidHistorySignature),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // Reset and change bits in the first history
        t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        t2.history[0].signature[2] = t2.history[1].signature[2] + 1;
        t2.history[0].signature[3] = t2.history[1].signature[3] + 1;
        assert_eq!(
            Err(BrioletteErrorCode::InvalidHistorySignature),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // Reset and change bits in the  base
        t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        t2.base.as_mut().unwrap().signature[2] = t2.base.as_mut().unwrap().signature[2] + 1;
        t2.base.as_mut().unwrap().signature[3] = t2.base.as_mut().unwrap().signature[3] + 1;
        assert_ne!(
            Ok(true),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // Reset and change the group in the signed ticket in base
        t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        t2.base
            .as_mut()
            .unwrap()
            .transfer
            .as_mut()
            .unwrap()
            .recipient
            .as_mut()
            .unwrap()
            .ticket
            .as_mut()
            .unwrap()
            .tags
            .as_mut()
            .unwrap()
            .group_number = 9999;
        assert_ne!(
            Ok(true),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // Reset and change bits in the descriptor
        t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        t2.descriptor
            .as_mut()
            .unwrap()
            .value
            .as_mut()
            .unwrap()
            .whole = 100;
        assert_ne!(
            Ok(true),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        // Reset and change bits in the transfer tag
        t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        t2.history[1]
            .transfer
            .as_mut()
            .unwrap()
            .tags
            .push(token::Tag {
                value: Some(token::tag::Value::TrimmedFrom(vec![41])),
            });
        assert_eq!(
            Err(BrioletteErrorCode::InvalidHistorySignature),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );
        t2 = token::Token::decode(wd.pending_tokens.last().unwrap().as_slice()).unwrap();
        assert_eq!(
            Ok(true),
            t2.verify(
                wd.transfer_credential.group_public_key.as_ref().unwrap(),
                &wd.epoch.mint_signing_keys,
                &wd.epoch.ticket_signing_keys
            )
        );

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn withdraw_and_transfer_and_validate_and_double_spend() {
        let tokenmap_uri = setup_tokenmap().await;
        let registrar_uri = setup_registrar(tokenmap_uri.clone()).await;
        let clerk_uri = setup_clerk(tokenmap_uri.clone()).await;
        let mint_uri = setup_mint(tokenmap_uri.clone()).await;
        let validate_uri = setup_validate(clerk_uri.clone(), tokenmap_uri.clone()).await;
        let mut wd = WalletData::new(registrar_uri, clerk_uri, mint_uri, validate_uri);
        assert_eq!(wd.initialize_keys(b"test-id2"), true);
        assert_eq!(wd.initialize_credential().await, true);
        assert_eq!(wd.synchronize().await, true);
        assert_eq!(wd.get_tickets(5).await, true);
        assert_eq!(wd.tickets.len(), 5);
        assert_eq!(wd.withdraw(10).await, true);
        assert_eq!(wd.tokens.len(), 10);
        assert_eq!(wd.tickets.len(), 4);
        // Not popping so we can easily reuse it.
        let destination: token::SignedTicket = wd.tickets.last().unwrap().clone().into();
        let destination_addr = destination.encode_to_vec();
        assert_eq!(wd.transfer(10, destination_addr), true);
        assert_eq!(wd.pending_tokens.len(), 10);
        // Give us our tokens back
        let mut tokens: Vec<token::Token> = vec![];
        while let Some(tok) = wd.pending_tokens.pop() {
            wd.tokens
                .push(token::Token::decode(tok.as_slice()).unwrap().into());
            tokens.push(token::Token::decode(tok.as_slice()).unwrap());
        }
        assert_eq!(wd.validate().await, true);
        // Now let's try a double spend by clearing the history then retransferring.
        let mut ds_token = tokens.pop().unwrap();
        ds_token.history.clear();
        wd.tokens.push(ds_token.into());
        let next_dest: token::SignedTicket = wd.tickets[1].clone().into();
        assert_eq!(wd.transfer(1, next_dest.encode_to_vec()), true);
        // Now move it back to our token list
        while let Some(tok) = wd.pending_tokens.pop() {
            wd.tokens
                .push(token::Token::decode(tok.as_slice()).unwrap().into());
            tokens.push(token::Token::decode(tok.as_slice()).unwrap());
        }
        // Validate should fail...
        assert_eq!(wd.validate().await, false);
        // TODO: check the revocation database.

        teardown();
    }

    pub fn teardown() {
        let remaining = TOKENMAP_RUNNING.fetch_sub(1, Ordering::SeqCst);
        if remaining != 0 {
            return;
        }
        // This is best effort hacky. Clean it up later, (TODO)
        for entry in glob("tokenmap.*.db").expect("Failed to read glob pattern") {
            match entry {
                Ok(path) => std::fs::remove_file(path).unwrap(),
                Err(e) => println!("{:?}", e),
            }
        }
    }
}
