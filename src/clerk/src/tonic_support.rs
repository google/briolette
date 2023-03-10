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

use crate::server::BrioletteClerk;
use briolette_proto::briolette::clerk::clerk_server::Clerk;
use briolette_proto::briolette::clerk::{
    AddEpochReply, EpochReply, EpochRequest, EpochUpdate, GetTicketsReply, GetTicketsRequest,
};
use tonic::{Request, Response, Status};

use std::convert::Into;

#[tonic::async_trait]
impl Clerk for BrioletteClerk {
    async fn get_epoch(
        &self,
        request: Request<EpochRequest>,
    ) -> Result<Response<EpochReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.get_epoch_impl(&message);
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }

    async fn add_epoch(
        &self,
        request: Request<EpochUpdate>,
    ) -> Result<Response<AddEpochReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.add_epoch_impl(&message);
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }

    async fn get_tickets(
        &self,
        request: Request<GetTicketsRequest>,
    ) -> Result<Response<GetTicketsReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.get_tickets_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
}
