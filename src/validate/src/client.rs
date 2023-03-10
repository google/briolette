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

use briolette_proto::briolette::validate::validate_client::ValidateClient;

use briolette_proto::briolette::token;
use briolette_proto::briolette::validate::ValidateTokensRequest;
use briolette_proto::briolette::Version;

use prost::Message;
use std::path::Path;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ValidateClient::connect("http://[::1]:50055").await?;

    let token_0 = std::fs::read(&Path::new("../mint/data/token.0.pb"))
        .expect("mint client generated token is missing");
    let token = token::Token::decode(token_0.as_slice()).unwrap();

    let request = ValidateTokensRequest {
        version: Version::Current.into(),
        tokens: vec![token],
    };
    println!("Calling validate: {:?}", request);
    let response = client.validate_tokens(request).await?;
    println!("Validate replied: {:?}", response);

    Ok(())
}
