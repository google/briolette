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

pub mod briolette;

// TODO(redpig) Bump these out into a separate helper crate to keep the dependencies
// lighter.
use log::*;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

// Helpers
pub mod vec_utils {
    pub fn vec_equal(l: &Vec<u8>, r: &Vec<u8>) -> bool {
        l.len() == r.len() && l.iter().zip(r).all(|(a, b)| *a == *b)
    }
}
#[tonic::async_trait]
pub trait BrioletteClientHelper: Sized {
    // Wraps the call to TonicClient::new(Channel)
    fn new_wrapper(channel: tonic::transport::Channel) -> Self;

    // Add support for the socket://localhost URI scheme and authority which
    // enables easy switching between UNIX domain sockets and TCP.
    async fn multiconnect(uri: &Uri) -> Result<Box<Self>, tonic::transport::Error> {
        let channel = match uri.scheme_str() {
            Some("socket") => {
                Endpoint::from(uri.clone())
                    .connect_with_connector(service_fn(|uri: Uri| {
                        info!("Connecting to socket at {:?}", uri);
                        // N.b., format!() is used to extract path() without creating a local reference in this
                        //       function, which will then go out of scope.
                        // TODO(redpig) Send pull request updating uds example in tonic.
                        UnixStream::connect(format!("{}", uri.path()))
                    }))
                    .await
            }
            _ => Endpoint::from(uri.clone()).connect().await,
        };
        if channel.is_ok() {
            trace!("Client channel connection established");
            Ok(Box::new(Self::new_wrapper(channel.unwrap())))
        } else {
            Err(channel.err().unwrap())
        }
    }
}
