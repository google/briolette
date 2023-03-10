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

use crate::server::BrioletteTokenMap;
use briolette_proto::briolette::tokenmap::token_map_server::TokenMap;
use briolette_proto::briolette::tokenmap::{
    ArchiveReply, ArchiveRequest, RevocationDataReply, RevocationDataRequest, StoreTicketsReply,
    StoreTicketsRequest, UpdateReply, UpdateRequest,
};
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl TokenMap for BrioletteTokenMap {
    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<UpdateReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.update_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
    async fn store_tickets(
        &self,
        request: Request<StoreTicketsRequest>,
    ) -> Result<Response<StoreTicketsReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.store_tickets_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
    async fn revocation_data(
        &self,
        request: Request<RevocationDataRequest>,
    ) -> Result<Response<RevocationDataReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.revocation_data_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
    async fn archive(
        &self,
        request: Request<ArchiveRequest>,
    ) -> Result<Response<ArchiveReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.archive_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
}
