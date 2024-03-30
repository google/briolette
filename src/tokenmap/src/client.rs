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

use briolette_proto::briolette::tokenmap::token_map_client::TokenMapClient;
use briolette_proto::briolette::tokenmap::{
    revocation_data_request::Select, RevocationDataRequest, SelectGroup,
};
use briolette_proto::BrioletteClientHelper;
use clap::Parser as ClapParser;

use tokio;
use tonic::transport::Uri;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Address to listen on
    #[arg(
        short = 's',
        long,
        value_name = "URI",
        default_value = "http://[::1]:50054"
    )]
    server_address: String,
    // TODO(redpig) add different commands
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut client = TokenMapClient::multiconnect(&Uri::try_from(args.server_address)?).await?;

    let request = RevocationDataRequest {
        select: Some(Select::Group(SelectGroup::All.into())),
    };
    println!("Calling tokenmap: {:?}", request);
    let response = client.revocation_data(request).await?;
    println!("Response: {:?}", response);

    Ok(())
}
