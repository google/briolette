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
use briolette_proto::BrioletteClientHelper;

use prost::Message;
use std::path::PathBuf;
use tokio;
use tonic::transport::Uri;

use clap::Parser as ClapParser;

#[derive(ClapParser, Debug)]
#[command(author, version)]
#[command(about = "basic integration test client for validate")]
struct Args {
    // Path to a token to validate
    #[arg(
        short = 't',
        long,
        value_name = "FILE",
        default_value = "data/wallet/token.0.pb"
    )]
    token: PathBuf,
    // Validate server URI
    #[arg(
        short = 'c',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50055"
    )]
    validate_uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut client = ValidateClient::multiconnect(&Uri::try_from(&args.validate_uri)?).await?;

    let token_0 = std::fs::read(&args.token).expect("mint client generated token is missing");
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
