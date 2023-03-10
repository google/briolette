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

use crate::{Agent, Population, PopulationError, Simulation};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use fnv::{FnvHashMap, FnvBuildHasher};


// A default population implementation


// TODO: Move out to examples or extras
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "S: Simulation")]
pub struct SimulationPopulation<S>
where
    S: Simulation,
{
    // TODO: Add iter wrapper
    pub agents: HashMap<usize, Agent<S::Data>, FnvBuildHasher>,
    pub next_id: usize,
}

impl<S: Simulation> SimulationPopulation<S> {
    pub fn new() -> Self {
        Self {
            agents: FnvHashMap::default(),
            next_id: 0,
        }
    }
}

impl<S: Simulation> Population<S> for SimulationPopulation<S>
{
    fn choose<R>(&self, rng: &mut R) -> Option<&Agent<S::Data>>
    where
        R: Rng + ?Sized,
    {
        // TODO: With a callback, this would allow a sim to choose from a filtered list.
        self.agents.values().choose(rng)
    }

    fn new_agents(&mut self, data: &S::Data, num: usize) {
        let mut count = num;
        while count > 0 {
            self.agents.insert(
                self.next_id,
                Agent {
                    id: self.next_id,
                    data: data.clone(),
                },
            );
            count -= 1;
            self.next_id += 1;
        }
    }
    fn get(&self, id: usize) -> Result<&Agent<S::Data>, PopulationError> {
        if let Some(agent) = self.agents.get(&id) {
            Ok(agent)
        } else {
            Err(PopulationError::InvalidAgentId)
        }
    }
    // Can update or insert and overwrites any existing entry.
    fn update(&mut self, agent: &Agent<S::Data>) {
        self.agents.insert(agent.id, agent.clone());
    }

    fn get_many(&self, id_range: std::ops::Range<usize>) -> Vec<Agent<S::Data>> {
        // TODO: Move to get_many_mut when it goes stable
        let mut found = vec![];
        for id in id_range {
            let maybe_entry = self.agents.get(&id);
            if let Some(entry) = maybe_entry {
                found.push(entry.clone());
            }
        }
        found
    }
    fn get_mut(&mut self, id: usize) -> Result<&mut Agent<S::Data>, PopulationError> {
        if let Some(agt) = self.agents.get_mut(&id) {
            Ok(agt)
        } else {
            Err(PopulationError::InvalidAgentId)
        }
    }
    fn len(&self) -> usize {
        return self.agents.len();
    }

    fn for_each(&self, c: &dyn Fn(&Agent<S::Data>) -> ()) {
        for agent in &self.agents { c(agent.1); }
    }
    fn for_each_mut(&mut self, c: &dyn Fn(&mut Agent<S::Data>) -> ()) {
        for agent in &mut self.agents { c(agent.1); }
    }
    fn remove(&mut self, id: &usize) {
        self.agents.remove(&id);
    }
}
