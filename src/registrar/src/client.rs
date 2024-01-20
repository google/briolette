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
use briolette_proto::briolette::registrar::registrar_client::RegistrarClient;
use briolette_proto::briolette::registrar::{
    Algorithm, CredentialRequest, HardwareId, RegisterRequest, SecurityLevel, Signature,
};
use briolette_proto::briolette::Version;
use briolette_proto::BrioletteClientHelper;

use sha256::digest;
use std::path::Path;
use tokio;
use tonic::transport::Uri;

#[derive(Clone, Default)]
struct KeyRequest {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RegistrarClient::multiconnect(&Uri::try_from("http://[::1]:50051")?).await?;

    let mut network_req = KeyRequest::default();
    let mut transfer_req = KeyRequest::default();
    // Token Key must include a signature over the hwid.
    let id_string: String = String::from("vendor:hw:sw:0012848734289738901879hc982");
    let hw_id: Vec<u8> = digest(id_string).into_bytes();
    let mut ret = v0::generate_wallet_keypair(
        &hw_id,
        &mut transfer_req.secret_key,
        &mut transfer_req.public_key,
    );
    if ret == false {
        eprintln!("Failed to generate token credential");
    }
    // The network request must include a signature over the token public key.
    ret = v0::generate_wallet_keypair(
        &transfer_req.public_key,
        &mut network_req.secret_key,
        &mut network_req.public_key,
    );
    if ret == false {
        eprintln!("Failed to generate network credential");
        return Ok(());
    }

    let request = tonic::Request::new(RegisterRequest {
        version: Version::Current.into(),
        hwid: Some(HardwareId {
            vendor_id: 1,
            software_id: 0,
            hardware_id: 1,
            hw_id: hw_id,
            security: SecurityLevel::Low.into(),
        }),
        hwid_signature: Some(Signature {
            algorithm: Algorithm::None.into(),
            signature: vec![],
            public_key: vec![],
        }),
        network_credential: Some(CredentialRequest {
            public_key: network_req.public_key,
        }),
        transfer_credential: Some(CredentialRequest {
            public_key: transfer_req.public_key,
        }),
    });

    let response = client.register_call(request).await?;
    println!("RESPONSE={:?}", response);
    // Write out the credentials to disk.
    let msg = response.into_inner();
    if let Some(nac_cred) = msg.network_credential {
        std::fs::write(&Path::new("data/wallet/nac.cred"), nac_cred.credential).unwrap();
        std::fs::write(&Path::new("data/wallet/nac.gpk"), nac_cred.group_public_key).unwrap();
        std::fs::write(&Path::new("data/wallet/nac.sk"), network_req.secret_key).unwrap();
    }
    if let Some(ttc_cred) = msg.transfer_credential {
        std::fs::write(&Path::new("data/wallet/ttc.cred"), ttc_cred.credential).unwrap();
        std::fs::write(&Path::new("data/wallet/ttc.gpk"), ttc_cred.group_public_key).unwrap();
        std::fs::write(&Path::new("data/wallet/ttc.sk"), transfer_req.secret_key).unwrap();
    }

    Ok(())
}
