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

tonic::include_proto!("briolette");
use prost::Message;
use rusqlite;
use tonic::{Code, Status};

/// Convert the response from *_impl to tonic::Status
impl Into<Status> for Error {
    fn into(self) -> Status {
        let mut buf = vec![];
        self.encode(&mut buf).unwrap();
        Status::with_details(
            Code::InvalidArgument,
            ErrorCode::from_i32(self.code)
                .unwrap_or(ErrorCode::InvalidMissingFields)
                .as_str_name(),
            bytes::Bytes::from(buf),
        )
    }
}

impl From<rusqlite::Error> for Error {
    fn from(_item: rusqlite::Error) -> Self {
        Error {
            code: ErrorCode::DatabaseInteractionError.into(),
        }
    }
}

impl From<ErrorCode> for Error {
    fn from(item: ErrorCode) -> Self {
        Error { code: item.into() }
    }
}

pub trait ServiceMapInterface {
    fn add(&mut self, name: ServiceName, uri: &String);
    fn get(&self, name: ServiceName) -> Vec<String>;
    fn remove_all(&mut self, name: ServiceName) -> bool;
}

impl ServiceMapInterface for Option<ServiceMap> {
    fn add(&mut self, name: ServiceName, uri: &String) {
        match self {
            None => {
                let sm = self.insert(ServiceMap::default());
                sm.add(name, uri);
            }
            Some(x) => x.add(name, uri),
        }
    }

    fn get(&self, name: ServiceName) -> Vec<String> {
        match self {
            None => vec![],
            Some(x) => x.get(name),
        }
    }

    fn remove_all(&mut self, name: ServiceName) -> bool {
        match self {
            None => false,
            Some(x) => x.remove_all(name),
        }
    }
}

impl ServiceMapInterface for ServiceMap {
    fn add(&mut self, name: ServiceName, uri: &String) {
        let mut entry = ServiceMapEntry::default();
        entry.name = name as i32;
        entry.uri = uri.clone();
        self.services.push(entry);
    }

    fn get(&self, name: ServiceName) -> Vec<String> {
        self.services
            .iter()
            .filter(|entry| entry.name == name as i32)
            .map(|entry| entry.uri.clone())
            .collect()
    }

    fn remove_all(&mut self, name: ServiceName) -> bool {
        let cnt = self.services.len();
        self.services.retain(|entry| entry.name != name as i32);
        // Return true if anything was removed.
        cnt > self.services.len()
    }
}

pub mod token;

pub mod validate {
    tonic::include_proto!("briolette.validate");

    use crate::BrioletteClientHelper;
    impl BrioletteClientHelper for validate_client::ValidateClient<tonic::transport::Channel> {
        fn new_wrapper(channel: tonic::transport::Channel) -> Self {
            Self::new(channel)
        }
    }
}

pub mod tokenmap {
    tonic::include_proto!("briolette.tokenmap");

    use crate::BrioletteClientHelper;
    impl BrioletteClientHelper for token_map_client::TokenMapClient<tonic::transport::Channel> {
        fn new_wrapper(channel: tonic::transport::Channel) -> Self {
            Self::new(channel)
        }
    }
}

pub mod mint {
    tonic::include_proto!("briolette.mint");

    use crate::BrioletteClientHelper;
    impl BrioletteClientHelper for mint_client::MintClient<tonic::transport::Channel> {
        fn new_wrapper(channel: tonic::transport::Channel) -> Self {
            Self::new(channel)
        }
    }
}

pub mod clerk;

pub mod registrar {
    tonic::include_proto!("briolette.registrar");

    use crate::BrioletteClientHelper;
    impl BrioletteClientHelper for registrar_client::RegistrarClient<tonic::transport::Channel> {
        fn new_wrapper(channel: tonic::transport::Channel) -> Self {
            Self::new(channel)
        }
    }
}

pub mod receiver {
    tonic::include_proto!("briolette.receiver");

    use crate::BrioletteClientHelper;
    impl BrioletteClientHelper for receiver_client::ReceiverClient<tonic::transport::Channel> {
        fn new_wrapper(channel: tonic::transport::Channel) -> Self {
            Self::new(channel)
        }
    }
}

pub mod swapper {
    tonic::include_proto!("briolette.swapper");

    use crate::BrioletteClientHelper;
    impl BrioletteClientHelper for swapper_client::SwapperClient<tonic::transport::Channel> {
        fn new_wrapper(channel: tonic::transport::Channel) -> Self {
            Self::new(channel)
        }
    }
}
