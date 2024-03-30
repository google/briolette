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

use crate::server::BrioletteSwapper;
use briolette_proto::briolette::swapper::swapper_server::Swapper;
use briolette_proto::briolette::swapper::{
    GetDestinationReply, GetDestinationRequest, SwapTokensReply, SwapTokensRequest,
};
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl Swapper for BrioletteSwapper {
    async fn swap_tokens(
        &self,
        request: Request<SwapTokensRequest>,
    ) -> Result<Response<SwapTokensReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.swap_tokens_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
    async fn get_destination(
        &self,
        request: Request<GetDestinationRequest>,
    ) -> Result<Response<GetDestinationReply>, Status> {
        let message = request.into_inner();
        let maybe_reply = self.get_destination_impl(&message).await;
        match maybe_reply {
            Ok(reply) => Ok(Response::new(reply)),
            Err(status) => Err(status.into()),
        }
    }
}
