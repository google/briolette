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

use crate::server::BrioletteRegistrar;
use briolette_proto::briolette::registrar::registrar_server::Registrar;
use briolette_proto::briolette::registrar::{RegisterReply, RegisterRequest};
use tonic::{Request, Response, Status};

use std::convert::Into;

#[tonic::async_trait]
impl Registrar for BrioletteRegistrar {
    async fn register_call(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.register_call_impl(&message);
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
}
