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

use crate::server::BrioletteReceiver;
use briolette_proto::briolette::receiver::receiver_server::Receiver;
use briolette_proto::briolette::receiver::*;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl Receiver for BrioletteReceiver {
    async fn initiate(
        &self,
        request: Request<InitiateRequest>,
    ) -> Result<Response<InitiateReply>, Status> {
        let peer = request.remote_addr().clone();
        let message = request.into_inner();
        let maybe_reply = self.initiate_impl(&message, peer).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
    async fn gossip(
        &self,
        request: Request<GossipRequest>,
    ) -> Result<Response<GossipReply>, Status> {
        let peer = request.remote_addr().clone();
        let message = request.into_inner();
        let maybe_reply = self.gossip_impl(&message, peer);
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
    async fn transact(
        &self,
        request: Request<TransactRequest>,
    ) -> Result<Response<TransactReply>, Status> {
        let peer = request.remote_addr().clone();
        let message = request.into_inner();
        let maybe_reply = self.transact_impl(&message, peer).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }

    async fn transfer(
        &self,
        request: Request<TransferRequest>,
    ) -> Result<Response<TransferReply>, Status> {
        let peer = request.remote_addr().clone();
        let message = request.into_inner();
        let maybe_reply = self.transfer_impl(&message, peer).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
}
