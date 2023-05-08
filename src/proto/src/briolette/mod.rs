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

pub mod token;

pub mod validate {
    tonic::include_proto!("briolette.validate");
}

pub mod tokenmap {
    tonic::include_proto!("briolette.tokenmap");
}

pub mod mint {
    tonic::include_proto!("briolette.mint");
}

pub mod clerk;

pub mod registrar {
    tonic::include_proto!("briolette.registrar");
}

pub mod receiver {
    tonic::include_proto!("briolette.receiver");
}

pub mod swapper {
    tonic::include_proto!("briolette.swapper");
}
