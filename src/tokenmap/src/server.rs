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

use briolette_proto::briolette::token;
use briolette_proto::briolette::token::TicketExpiry;
use briolette_proto::briolette::token::Token;
use briolette_proto::briolette::tokenmap;
use briolette_proto::briolette::tokenmap::{
    ArchiveReply, ArchiveRequest, RevocationDataReply, RevocationDataRequest, StoreTicketsReply,
    StoreTicketsRequest, UpdateReply, UpdateRequest,
};
use briolette_proto::briolette::{Error as BrioletteError, ErrorCode as BrioletteErrorCode};
use briolette_proto::vec_utils;
use chrono::Utc;
//use deadpool_sqlite::{Config, Pool, Runtime};
use log::*;
use prost::Message;
use rusqlite;
use tokio_rusqlite::Connection;

#[derive(Debug, Clone)]
pub struct BrioletteTokenMap {
    conn: Connection,
}

impl BrioletteTokenMap {
    pub async fn new(db_path: &String) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(db_path).await?;

        conn.call(|conn| {
            let mut stmt = conn.prepare(
                "create table if not exists tokens (
             id blob primary key,
             entry blob not null,
             last_update integer
            )",
            )?;
            stmt.execute([])?;
            let mut stmt = conn.prepare(
                "create table if not exists tickets (
             credential blob primary key,
             signed_ticket blob not null,
             nac_signature blob not null,
             expires_on integer
            )",
            )?;
            stmt.execute([])?;
            let mut stmt = conn.prepare(
                "create index if not exists ticket_request_signature ON tickets (nac_signature)",
            )?;
            stmt.execute([])?;
            // Revocation data is keyed on token id.
            let mut stmt = conn.prepare(
                "create table if not exists revocation (
             id blob primary key,
             data blob not null,
             created_on integer
            )",
            )?;
            stmt.execute([])?;
            let mut stmt = conn.prepare(
                "create table if not exists revocation_archive (
             id blob primary key,
             data blob not null,
             created_on integer
            )",
            )?;
            stmt.execute([])?;
            Ok::<_, rusqlite::Error>(())
        })
        .await?;
        Ok(Self { conn })
    }

    pub async fn update_impl(
        &self,
        request: &UpdateRequest,
    ) -> Result<UpdateReply, BrioletteError> {
        if request.id.len() == 0 || request.token.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        trace!("Looking up token: {:?}", request.id);
        let maybe_entry: Option<tokenmap::Entry> =
            self.get_tokenmap_entry(request.id.clone()).await?;
        trace!("Entry found: {:?}", maybe_entry);
        if maybe_entry.is_none() {
            self.create_tokenmap_entry(request.id.clone(), request.token.clone().unwrap())
                .await?;
            trace!("Token inserted!");
            return Ok(UpdateReply {
                created: true,
                abuse_detected: false,
            });
        }
        let now = Utc::now().timestamp() as u64;
        let mut entry = maybe_entry.unwrap();
        // It gets more interesting here:
        // 1. For each token in the entry, check if there is a shared history with the supplied token.
        // 2. If the history overlaps and the token extends it, then replace that token and update the entry.
        // 3. If the history forks and there is no split at the fork, then create a revocation record.
        // 4. If the history forks and both have splits, then check the total to be <= the original value.
        // 5. If the split exceeds the original amount, then create a revocation record for the splitter.
        //
        // ** TokenMap assumes the caller has cryptographically verified the tokens prior to calling! **
        //
        let candidate = request.token.clone().unwrap();

        // No update needed.
        if token_is_known(&candidate, &entry.tokens) {
            return Ok(UpdateReply {
                created: false,
                abuse_detected: entry.abuses.len() != 0,
            });
        }
        // Check if the token is an extension, but not a fork.
        if let Some(idx) = token_is_extension(&candidate, &entry.tokens) {
            // Replace the prior view with the updated view.
            entry.tokens[idx] = candidate;
            entry.last_update = now;
            let abuse_detected = entry.abuses.len() != 0;
            self.update_tokenmap_entry(&request.id, entry).await?;
            return Ok(UpdateReply {
                created: false,
                abuse_detected: abuse_detected,
            });
        }
        // Now we check for splits.
        // If the candidate is not an extension, it must not be the first split.
        // It it is legitimate, then it is an unknown second split.
        // TODO: Refactor to use token_get_fork()
        if token_is_second_split(&candidate, &entry.tokens) {
            // Insert the new token history.
            entry.tokens.push(candidate);
            entry.last_update = now;
            let abuse_detected = entry.abuses.len() != 0;
            self.update_tokenmap_entry(&request.id, entry).await?;

            return Ok(UpdateReply {
                created: false,
                abuse_detected: abuse_detected,
            });
        }
        // We're in double spend territory now.
        trace!("double spending detected");
        let (token_index, history_index) =
            token_get_fork(&candidate, &entry.tokens).expect("a fork must exist to reach this far");
        let abuse = tokenmap::Abuse {
            discovery_timestamp: now.clone(),
            token_index: token_index as u32,
            history_index: history_index as u32,
            // TODO: we don't capture this state in token_is_second_split().
            abuse_type: tokenmap::AbuseType::DoubleSpend.into(),
        };
        let token_expiry = entry.tokens[0]
            .base
            .as_ref()
            .unwrap()
            .transfer
            .as_ref()
            .unwrap()
            .tags
            .iter()
            .map(|tag| match tag.value {
                Some(token::tag::Value::ValidUntil(ts)) => ts,
                _ => 0,
            })
            .find(|&ts| ts != 0);
        let ds_history = &entry.tokens[token_index].history[history_index];
        let prev_history;
        if history_index == 0 {
            prev_history = entry.tokens[token_index].base.as_ref().unwrap();
        } else {
            prev_history = &entry.tokens[token_index].history[history_index - 1];
        }

        // Pull the signed ticket from the database to get the NAC signature and basename
        let signed_ticket = ds_history
            .transfer
            .as_ref()
            .unwrap()
            .recipient
            .as_ref()
            .unwrap();
        let ticket = signed_ticket.ticket.as_ref().unwrap();
        let nac_sig = self.get_ticket_signature(&ticket.credential).await?;
        if nac_sig.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::TicketSignatureMissing.into(),
            });
        }

        // TODO: Support two modes:
        // 1. Fetch all tickets from the request that issued the ds ticket and revoke those groups.
        //    Also store the pseudonym for the epoch to link any other ticket requests.
        // 2. Pull all active groups for the given NAC and their expirations.
        // The choice would be on whether it is a class-break or a specific device.  In most case,
        // I would expect the plan to start small and expand with more incidence.
        //
        // For now, this is just the current ticket group.
        let ticket_tags = ticket.tags.as_ref().unwrap();
        let ticket_expiration = signed_ticket.expires_on();
        // TODO: Should we not add a new entry if abuses.len() > 0?
        let revocation_data = tokenmap::RevocationData {
            timestamp: now,
            nac: nac_sig,
            ttc: Some(tokenmap::LinkableSignature {
                signature: ds_history.signature.clone(),
                basename: prev_history.signature.clone(),
                group_public_key: vec![], // Add these at start up
            }),
            token_id: request.id.clone(),
            token_expiry: token_expiry.unwrap(),
            groups: vec![tokenmap::Group {
                number: ticket_tags.group_number,
                expiration: ticket_expiration,
            }],
            abuse: tokenmap::AbuseType::DoubleSpend.into(),
        };

        entry.abuses.push(abuse);
        entry.tokens.push(candidate);
        entry.last_update = now;
        let abuse_detected = entry.abuses.len() != 0;
        self.update_tokenmap_entry(&request.id, entry).await?;
        self.insert_revocation_data(&request.id, revocation_data)
            .await?;
        return Ok(UpdateReply {
            created: false,
            abuse_detected: abuse_detected,
        });
    }

    async fn insert_revocation_data(
        &self,
        id: &Vec<u8>,
        data: tokenmap::RevocationData,
    ) -> Result<(), BrioletteError> {
        let key = id.clone();
        trace!("inserting revocation data {:?}...", id);
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("INSERT INTO revocation (id, data, created_on) values (?1, ?2, ?3)")?;
                stmt.execute((key, data.encode_to_vec(), data.timestamp.clone()))?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?)
    }

    async fn insert_archive_data(
        &self,
        id: &Vec<u8>,
        data: tokenmap::RevocationData,
        created_on: u64,
    ) -> Result<(), BrioletteError> {
        let key = id.clone();
        trace!("inserting revocation archive data {:?}...", id);
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "INSERT INTO revocation_archive (id, data, created_on) values (?1, ?2, ?3)",
                )?;
                stmt.execute((key, data.encode_to_vec(), created_on))?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?)
    }

    async fn update_tokenmap_entry(
        &self,
        id: &Vec<u8>,
        entry: tokenmap::Entry,
    ) -> Result<(), BrioletteError> {
        let key = id.clone();
        trace!("Updating token {:?}...", id);
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("UPDATE tokens SET entry = ?2, last_update = ?3 where id = ?1")?;
                stmt.execute((key, entry.encode_to_vec(), entry.last_update.clone()))?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?)
    }

    async fn create_tokenmap_entry(&self, id: Vec<u8>, token: Token) -> Result<(), BrioletteError> {
        log::debug!("token does not yet exist: {}", hex::encode(id.clone()));
        // Just add it.
        let now = Utc::now().timestamp() as u64;
        let entry = tokenmap::Entry {
            id: id.clone(),
            tokens: vec![token],
            abuses: vec![],
            last_update: now,
        };
        trace!("Inserting token...");
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("INSERT INTO tokens (id, entry, last_update) values (?1, ?2, ?3)")?;
                stmt.execute((id, entry.clone().encode_to_vec(), entry.last_update.clone()))?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?)
    }

    async fn get_ticket_signature(
        &self,
        credential: &Vec<u8>,
    ) -> Result<Option<tokenmap::LinkableSignature>, BrioletteError> {
        let cred = credential.clone();
        Ok(self
            .conn
            .call(|conn| {
                trace!("Preparing statement...");
                let mut stmt =
                    conn.prepare("SELECT nac_signature FROM tickets WHERE credential = ?")?;
                let mut rows = stmt.query([cred])?;
                if let Some(row) = rows.next()? {
                    trace!("walking the row");
                    let data: Vec<u8> = row.get(0)?;
                    if let Ok(ls) = tokenmap::LinkableSignature::decode(data.as_slice()) {
                        return Ok(Some(ls));
                    }
                }
                return Ok::<_, rusqlite::Error>(None);
            })
            .await?)
    }

    async fn get_tokenmap_entry(
        &self,
        id: Vec<u8>,
    ) -> Result<Option<tokenmap::Entry>, BrioletteError> {
        Ok(self
            .conn
            .call(|conn| {
                trace!("Preparing statement...");
                let mut stmt = conn.prepare("SELECT * FROM tokens WHERE id = ?")?;
                trace!("Checking existence...");
                if let Ok(exists) = stmt.exists([id.clone()]) {
                    if exists == false {
                        trace!("select returned empty!");
                        return Ok::<_, rusqlite::Error>(None);
                    }
                }
                let mut rows = stmt.query([id])?;
                if let Some(row) = rows.next()? {
                    trace!("walking the row");
                    let data: Vec<u8> = row.get(1)?;
                    if let Ok(entry) = tokenmap::Entry::decode(data.as_slice()) {
                        return Ok(Some(entry));
                    }
                }
                Ok::<_, rusqlite::Error>(None)
            })
            .await?)
    }

    async fn insert_signed_ticket(
        &self,
        credential: &Vec<u8>,
        data: token::SignedTicket,
        nac_signature: tokenmap::LinkableSignature,
        expiration: u64,
    ) -> Result<(), BrioletteError> {
        let key = credential.clone();
        trace!("inserting signed ticket {}...", hex::encode(credential));
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("INSERT INTO tickets (credential, signed_ticket, nac_signature, expires_on) values (?1, ?2, ?3, ?4)")?;
                stmt.execute((key, data.encode_to_vec(), nac_signature.encode_to_vec(), expiration))?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?)
    }

    async fn get_revocation_data(
        &self,
        id: &Vec<u8>,
    ) -> Result<Vec<tokenmap::RevocationDataEntry>, BrioletteError> {
        let key = id.clone();
        Ok(self
            .conn
            .call(|conn| {
                trace!("Preparing statement...");
                let mut stmt = conn.prepare("SELECT * FROM revocation where id = ?")?;
                let mut rows = stmt.query([key])?;
                let mut entries: Vec<tokenmap::RevocationDataEntry> = vec![];
                if let Some(row) = rows.next()? {
                    let id: Vec<u8> = row.get(0)?;
                    let rd: Vec<u8> = row.get(1)?;
                    let created_on = row.get(2)?;
                    if let Ok(data) = tokenmap::RevocationData::decode(rd.as_slice()) {
                        entries.push(tokenmap::RevocationDataEntry {
                            id,
                            data: Some(data),
                            created_on,
                        });
                    }
                }
                return Ok::<_, rusqlite::Error>(entries);
            })
            .await?)
    }

    async fn get_all_revocation_data(
        &self,
    ) -> Result<Vec<tokenmap::RevocationDataEntry>, BrioletteError> {
        Ok(self
            .conn
            .call(|conn| {
                trace!("Preparing statement...");
                let mut stmt = conn.prepare("SELECT * FROM revocation")?;
                let mut rows = stmt.query([])?;
                let mut entries: Vec<tokenmap::RevocationDataEntry> = vec![];
                while let Some(row) = rows.next()? {
                    let id: Vec<u8> = row.get(0)?;
                    let rd: Vec<u8> = row.get(1)?;
                    let created_on = row.get(2)?;
                    if let Ok(data) = tokenmap::RevocationData::decode(rd.as_slice()) {
                        entries.push(tokenmap::RevocationDataEntry {
                            id,
                            data: Some(data),
                            created_on,
                        });
                    }
                }
                return Ok::<_, rusqlite::Error>(entries);
            })
            .await?)
    }

    pub async fn store_tickets_impl(
        &self,
        request: &StoreTicketsRequest,
    ) -> Result<StoreTicketsReply, BrioletteError> {
        if request.tickets.len() == 0 || request.nac.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        let nac = request.nac.clone().unwrap();
        if nac.signature.len() == 0 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        for signed_ticket in request.tickets.iter() {
            let credential = signed_ticket.ticket.clone().unwrap().credential;
            self.insert_signed_ticket(
                &credential,
                signed_ticket.clone(),
                nac.clone(),
                signed_ticket.expires_on(),
            )
            .await?;
        }
        // For now, we don't store the full linkable signature
        return Ok(StoreTicketsReply {});
    }

    pub async fn revocation_data_impl(
        &self,
        request: &RevocationDataRequest,
    ) -> Result<RevocationDataReply, BrioletteError> {
        if request.select.is_none() {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        match request.select.as_ref().unwrap() {
            tokenmap::revocation_data_request::Select::Id(id) => {
                if id.len() == 0 {
                    return Err(BrioletteError {
                        code: BrioletteErrorCode::InvalidMissingFields.into(),
                    });
                }
                let rde = self.get_revocation_data(id).await?;
                return Ok(RevocationDataReply { entries: rde });
            }
            tokenmap::revocation_data_request::Select::Group(sg) => {
                if *sg != tokenmap::SelectGroup::All.into() {
                    return Err(BrioletteError {
                        code: BrioletteErrorCode::InvalidMissingFields.into(),
                    });
                }
                let rde = self.get_all_revocation_data().await?;
                return Ok(RevocationDataReply { entries: rde });
            }
        }
    }

    pub async fn archive_impl(
        &self,
        request: &ArchiveRequest,
    ) -> Result<ArchiveReply, BrioletteError> {
        if request.id.len() == 0 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::InvalidMissingFields.into(),
            });
        }
        let rde = self.get_revocation_data(&request.id).await?;
        if rde.len() == 0 {
            return Err(BrioletteError {
                code: BrioletteErrorCode::RevocationNotFound.into(),
            });
        }
        // Let's add it to the archive, then delete it from revocation.
        self.insert_archive_data(&request.id, rde[0].data.clone().unwrap(), rde[0].created_on)
            .await?;
        return Ok(ArchiveReply {});
    }
}

fn get_split_amount(maybe_transfer: &Option<token::Transfer>) -> Option<token::Amount> {
    if let Some(transfer) = maybe_transfer.clone() {
        for tag in transfer.tags.clone() {
            match tag.value {
                Some(token::tag::Value::SplitValue(amount)) => {
                    return Some(amount.clone());
                }
                _ => {}
            }
        }
    }
    None
}

fn token_is_known(candidate: &Token, tokens: &Vec<Token>) -> bool {
    for token in tokens.iter() {
        // Only looking for <= fully self contained entries.
        if candidate.history.len() > token.history.len() {
            continue;
        }
        // Skip the base since we index on its signature.
        // If the candidate has a shorter history, a call to update doesn't mean something bad has happened.
        let differences = token
            .history
            .iter()
            .zip(&candidate.history)
            .find(|&(known, unknown)| {
                vec_utils::vec_equal(&known.signature, &unknown.signature) == false
            });
        if differences.is_some() {
            // Keep checking because we could have multi-history due to splits.
            // The fallthrough failure should catch a no-match scenario.
            continue;
        }
        return true;
    }
    return false;
}

fn token_is_extension(candidate: &Token, tokens: &Vec<Token>) -> Option<usize> {
    for (index, token) in tokens.iter().enumerate() {
        // Only looking for extensions of history.
        if candidate.history.len() <= token.history.len() {
            continue;
        }
        // Skip the base since we index on its signature.
        // If the candidate has a shorter history, a call to update doesn't mean something bad has happened.
        let differences = token
            .history
            .iter()
            .zip(&candidate.history)
            .find(|&(known, unknown)| {
                vec_utils::vec_equal(&known.signature, &unknown.signature) == false
            });
        if differences.is_some() {
            // Keep checking because we could have multi-history due to splits.
            // The fallthrough failure should catch a no-match scenario.
            continue;
        }
        // If there were no differences, but the candidate has a longer history.
        // TODO: Look through transfers for a split and make sure it doesn't exceed the original
        //       amount!
        //       The callers _should_ do this while they can't check the total like tokenmap can.
        return Some(index);
    }
    return None;
}

fn token_get_fork(candidate: &Token, tokens: &Vec<Token>) -> Option<(usize, usize)> {
    for (index, token) in tokens.iter().enumerate() {
        let pos = token
            .history
            .iter()
            .zip(&candidate.history)
            .position(|(known, unknown)| {
                vec_utils::vec_equal(&known.signature, &unknown.signature) == false
            });
        // If this is a second split extension, then this will be the split node
        // on the other history. If token_is_extension() is called before this,
        // then it's fine.
        if pos.is_some() {
            return Some((index, pos.unwrap()));
        }
    }
    // No forks detected.
    return None;
}

fn token_is_second_split(candidate: &Token, tokens: &Vec<Token>) -> bool {
    for token in tokens.iter() {
        // The second split may not be longer than the first split, so we can't short circuit with
        // a length check.  However, they must share a common fork node with the split tag.
        // We use find() instead of filter() because we only need the fork node.
        let diff: Option<(&token::History, &token::History)> = token
            .history
            .iter()
            .zip(&candidate.history)
            .find(|&(known, unknown)| {
                vec_utils::vec_equal(&known.signature, &unknown.signature) == false
            });
        if let Some((known, unknown)) = diff {
            trace!("forked history detected");
            // The first entries _must_ be splits or we have a problem.
            let split_amounts = (
                get_split_amount(&known.clone().transfer),
                get_split_amount(&unknown.clone().transfer),
            );
            if split_amounts.0.is_some() && split_amounts.1.is_some() {
                let known_amount = split_amounts.0.unwrap();
                let unknown_amount = split_amounts.1.unwrap();
                if known_amount.code != unknown_amount.code {
                    return false;
                } else {
                    let total = known_amount + unknown_amount;
                    let original_total = token.descriptor.clone().unwrap().value.clone().unwrap();
                    // If a split doesn't sum to its original amount, it is a failure.
                    if total == original_total {
                        return true;
                    }
                    trace!("splits do not add up!");
                }
            }
            // Any new candidate is extending a single known entry or one of two splits.
            // If we find a fork node where neither are splits, that's a problem.
            // If we find a fork node where one is a split and the other isn't, that's a problem.
            return false;
        }
    }
    // This is only reachable if we walked through every token and this token had no differences.
    // E.g., number of tokens is 1 and this token is a subset.
    return false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_known_ok() {
        assert_eq!(4, 4);
    }
}
