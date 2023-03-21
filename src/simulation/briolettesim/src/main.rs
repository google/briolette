// Copyright 2023 The Briolette Authors
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

//  Basic model describing the briolette digital currency system.
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};

use absim::clients::LocalSimulationClient;
use absim::extras::SimulationPopulation;
use absim::{
    Address, Agent, Enqueue, Event, EventQueue, Manager, ManagerInterface, Population, Simulation,
    WorldView,
};
use levy_distr::Levy;
use rand_distr::{Pareto, Uniform};
use rand_flight::Flight;
use rand_flight::Step;

#[derive(Debug)]
pub struct Simulator {
    //pub rng: Arc<RwLock<StdRng>>, // Interior Mutability!
    pub seed: u64,
    // TODO: hide this in absim
    pub clones: Arc<RwLock<usize>>,            // Interior Mutability
    pub helper: Arc<RwLock<SimulatorHelpers>>, // Violate ro-ness with interior mutability
}
impl Simulator {
    pub fn new(seed: u64, helper: SimulatorHelpers) -> Self {
        Self {
            seed: seed,
            clones: Arc::new(RwLock::new(0)),
            helper: Arc::new(RwLock::new(helper)),
        }
    }
    // TODO add error handling
    pub fn do_transaction(
        &self,
        view: &ViewData,
        helper: &mut SimulatorHelpers,
        source: &Agent<AgentData>,
        target: &Agent<AgentData>,
        amount: usize,
        double_spend: bool,
        pop: bool,
        coin_count: &mut usize,
        queue: &mut impl Enqueue<Self>,
    ) -> usize {
        let mut stats = Statistics::default();
        let mut count = 0;
        let txn_epoch = max(source.data.epoch, target.data.epoch);
        // Gossip here to ensure we're in sync.
        if source.data.epoch != target.data.epoch {
            queue.enqueue(
                Address::AgentId(source.id),
                Address::AgentId(target.id),
                EventData::Gossip(GossipData { epoch: txn_epoch }),
            );
            count += 1;
        }
        // We check for revocation of the peer based on the max() of their epochs.
        // While it is unlikely for a revoked party to share a revoked update, they shouldn't be
        // able to share a secure epoch time that doesn't include updates because the time and
        // hash/root hash must be linked.  If epochs don't need ordering, they can also just be
        // signatures over hashes, but we'd need to figure out how deltas apply then, etc.
        //
        // We also check if either is revoked now, pretended the receiving agent has vetted and
        // rejected.  This avoids doing rejections in the apply() phase.
        assert!(txn_epoch <= view.epoch);
        let mut rejected = false;
        if view.epochs[txn_epoch].revocation.contains(&source.id) {
            queue.enqueue(
                Address::AgentId(source.id),
                Address::NoAddress,
                EventData::RejectedTransact,
            );
            stats.txns_rejected_total += 1;
            rejected = true;
        } else if view.epochs[txn_epoch].revocation.contains(&target.id) {
            queue.enqueue(
                Address::NoAddress,
                Address::AgentId(target.id),
                EventData::RejectedTransact,
            );
            stats.txns_rejected_total += 1;
            rejected = true;
        } else {
            stats.txns_total += 1;
        }
        if source.data.role.is_consumer() && target.data.role.is_consumer() {
            stats.txns_p2p_rejected_total = stats.txns_rejected_total;
            stats.txns_p2p_total = stats.txns_total;
        } else if source.data.role.is_consumer() && target.data.role.is_merchant() {
            stats.txns_p2m_rejected_total = stats.txns_rejected_total;
            stats.txns_p2m_total = stats.txns_total;
        } else if source.data.role.is_merchant() && target.data.role.is_merchant() {
            stats.txns_m2m_rejected_total = stats.txns_rejected_total;
            stats.txns_m2m_total = stats.txns_total;
        } else if source.data.role.is_merchant() && target.data.role.is_bank() {
            stats.txns_m2b_rejected_total = stats.txns_rejected_total;
            stats.txns_m2b_total = stats.txns_total;
        } else if source.data.role.is_bank() && target.data.role.is_merchant() {
            stats.txns_b2m_rejected_total = stats.txns_rejected_total;
            stats.txns_b2m_total = stats.txns_total;
        } else if source.data.role.is_consumer() && target.data.role.is_bank() {
            stats.txns_p2b_rejected_total = stats.txns_rejected_total;
            stats.txns_p2b_total = stats.txns_total;
        } else if source.data.role.is_bank() && target.data.role.is_consumer() {
            stats.txns_b2p_rejected_total = stats.txns_rejected_total;
            stats.txns_b2p_total = stats.txns_total;
        } else if source.data.role.is_bank() && target.data.role.is_bank() {
            stats.txns_b2b_rejected_total = stats.txns_rejected_total;
            stats.txns_b2b_total = stats.txns_total;
        }

        if stats != Statistics::default() {
            queue.enqueue(
                Address::AgentId(source.id),
                Address::World,
                EventData::UpdateStatistics(stats),
            );
        }
        count += 1;

        // Don't process the txn if it is rejected by either party based on revocation.
        if rejected {
            return count + 1;
        }

        let mut coins = Vec::new();
        // Build the payload
        let mut coin_iter = source.data.coins.iter().rev(); // Work backwards to enable popping!
        for _c in 0..amount {
            if let Some(coin) = coin_iter.next() {
                coins.push(TransactionCoin {
                    coin: coin.clone(),
                    copy: double_spend,
                    popped: pop,
                });
                *coin_count += 1;
                // Assign the recipient.
                coins
                    .iter_mut()
                    .last()
                    .unwrap()
                    .coin
                    .history
                    .push(target.id);
                coins
                    .iter_mut()
                    .last()
                    .unwrap()
                    .coin
                    .step_history
                    .push(view.step);
                // Create a unique txn id
                coins
                    .iter_mut()
                    .last()
                    .unwrap()
                    .coin
                    .tx_history
                    .push(helper.get_uniform(10, 9223372036854775808));
            }
        }
        queue.enqueue(
            Address::AgentId(source.id),
            Address::AgentId(target.id),
            EventData::Transact(TransactData { coins: coins }),
        );
        count + 1
    }
}
// Create a stable way to maintained seeded randomness across view and client splits.
impl Clone for Simulator {
    fn clone(&self) -> Self {
        let mut c = self.clones.write().unwrap();
        // Let's avoid silliness.
        if *c == usize::MAX {
            *c = 0;
        } else {
            *c += 1;
        }
        let m: u64 = (*c).try_into().unwrap();
        let mut new_help = self.helper.read().unwrap().clone();
        new_help.rng = Box::new(SeedableRng::seed_from_u64(self.seed + m));
        Self {
            seed: self.seed,
            clones: Arc::new(RwLock::new(*c)),
            helper: Arc::new(RwLock::new(new_help)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Coin {
    id: usize, // Since our 0 history isn't unique
    value: usize,
    copied: bool, // True when a copy was made. This lets us track circulation of ds.
    history: Vec<usize>, // agent index. Later we will need group for quarantine
    tx_history: Vec<usize>, // this lets us add ephemerality to catch respend of the same coin to
    // the same agent A(1) -> A(2) will make the same provenance
    step_history: Vec<usize>, // tracks whcih step the tx took place in
}

// Used in the coin map to track counterfeiting impact
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct CoinState {
    coin: Coin,
    revoked: Option<usize>, // Step of revocation
    fork_txn: Option<usize>,
    forks: Vec<usize>, // List of known forks so we can accurately coin recoveries.
}

impl CoinState {
    pub fn new(coin: Coin) -> Self {
        CoinState {
            coin: coin,
            revoked: None,
            fork_txn: None,
            forks: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SyncState {
    id: usize,
    revocation: Vec<usize>, // list of agent ids for now.
    quarantine: Vec<usize>, // group ids to manage WID issuance?
    step: usize,            // Create at what step
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransactionCoin {
    coin: Coin,
    copy: bool,   // true to double spend
    popped: bool, // True if the coin has already been removed from the sender.
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransactData {
    coins: Vec<TransactionCoin>, // double spending is literal this way.
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct Statistics {
    potential_double_spender_max: usize,
    double_spenders_total: usize,
    double_spenders_revoked_total: usize,
    txns_total: usize,
    txns_p2p_total: usize,
    txns_p2m_total: usize,
    txns_m2m_total: usize,
    txns_b2m_total: usize,
    txns_m2b_total: usize,
    txns_b2p_total: usize,
    txns_p2b_total: usize,
    txns_b2b_total: usize,
    txns_p2p_rejected_total: usize,
    txns_p2m_rejected_total: usize,
    txns_m2m_rejected_total: usize,
    txns_b2m_rejected_total: usize,
    txns_m2b_rejected_total: usize,
    txns_b2p_rejected_total: usize,
    txns_p2b_rejected_total: usize,
    txns_b2b_rejected_total: usize,
    txns_rejected_total: usize,
    register_total: usize,
    synchronize_total: usize,
    coins_total: usize,
    coins_valid_total: usize,
    coins_double_spent_recovered: usize,
    coins_double_spent_recovered_repeats: usize,
    coins_double_spent_total: usize,
    double_spent_longest_life: usize,
    double_spent_most_txns: usize,
    validate_total: usize,
}

impl Statistics {
    pub fn update(&mut self, stats: &Statistics) {
        self.potential_double_spender_max += stats.potential_double_spender_max;
        self.double_spenders_total += stats.double_spenders_total;
        self.double_spenders_revoked_total += stats.double_spenders_revoked_total;
        self.txns_total += stats.txns_total;
        self.txns_p2p_total += stats.txns_p2p_total;
        self.txns_p2m_total += stats.txns_p2m_total;
        self.txns_m2m_total += stats.txns_m2m_total;
        self.txns_b2p_total += stats.txns_b2p_total;
        self.txns_p2b_total += stats.txns_p2b_total;
        self.txns_b2m_total += stats.txns_b2m_total;
        self.txns_m2b_total += stats.txns_m2b_total;
        self.txns_b2b_total += stats.txns_b2b_total;
        self.txns_p2p_rejected_total += stats.txns_p2p_rejected_total;
        self.txns_p2m_rejected_total += stats.txns_p2m_rejected_total;
        self.txns_m2m_rejected_total += stats.txns_m2m_rejected_total;
        self.txns_b2m_rejected_total += stats.txns_b2m_rejected_total;
        self.txns_m2b_rejected_total += stats.txns_m2b_rejected_total;
        self.txns_b2p_rejected_total += stats.txns_b2p_rejected_total;
        self.txns_p2b_rejected_total += stats.txns_p2b_rejected_total;
        self.txns_b2b_rejected_total += stats.txns_b2b_rejected_total;
        self.txns_rejected_total += stats.txns_rejected_total;
        self.register_total += stats.register_total;
        self.synchronize_total += stats.synchronize_total;
        self.coins_total += stats.coins_total;
        self.coins_valid_total += stats.coins_valid_total;
        self.coins_double_spent_total += stats.coins_double_spent_total;
        self.double_spent_longest_life += stats.double_spent_longest_life;
        self.double_spent_most_txns += stats.double_spent_most_txns;
        self.coins_double_spent_recovered += stats.coins_double_spent_recovered;
        self.coins_double_spent_recovered_repeats += stats.coins_double_spent_recovered_repeats;
        self.validate_total += stats.validate_total;
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ConsumerData {
    lifetime: usize, // in steps
    // Location native to Agent
    sync_probability: f64,
    sync_distribution: SupportedDistributions,
    p2m_probability: f64,
    p2m_distribution: SupportedDistributions,
    p2p_probability: f64,
    p2p_distribution: SupportedDistributions,
    double_spend_probability: f64,
    double_spend_distribution: SupportedDistributions,
    max_rejections: usize,
    move_distribution: SupportedDistributions,
    move_probability: f64,
    wids: usize,
    wid_low_watermark: usize,
    account_balance: usize,
    last_requested_step: usize,
    bank: usize,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct MerchantData {
    lifetime: usize, // in steps
    // Location native to Agent
    sync_probability: f64,
    sync_distribution: SupportedDistributions,
    account_balance: usize,
    last_tx_step: Option<usize>,
    bank: usize,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct BankData {
    holding: Vec<Coin>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    Consumer(ConsumerData),
    Merchant(MerchantData),
    Bank(BankData),
}

impl AgentRole {
    pub fn is_consumer(&self) -> bool {
        match self {
            AgentRole::Consumer(_) => true,
            _ => false,
        }
    }
    pub fn is_merchant(&self) -> bool {
        match self {
            AgentRole::Merchant(_) => true,
            _ => false,
        }
    }
    pub fn is_bank(&self) -> bool {
        match self {
            AgentRole::Bank(_) => true,
            _ => false,
        }
    }
}
impl Default for AgentRole {
    fn default() -> Self {
        AgentRole::Consumer(ConsumerData::default())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub struct AgentData {
    location: Location,
    registered: bool,
    epoch: usize,
    coins: Vec<Coin>,
    pending: Vec<Event<EventData>>, // Events which should be fired off in the next gen phase
    role: AgentRole,
}
impl Default for AgentData {
    fn default() -> Self {
        AgentData {
            location: Location(0, 0),
            registered: false,
            epoch: 0,
            coins: vec![],
            pending: vec![],
            role: AgentRole::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ResourceData {
    location: Location,
    class: ResourceClass,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PopulationAdd {
    data: AgentData,
    count: usize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PopulationDel {
    ids: Vec<usize>, // Agent ids
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RegisterData {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SynchronizeData {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ValidateData {
    coins: Vec<Coin>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ValidateResponseData {
    ok: Vec<usize>,          // coin.id
    counterfeit: Vec<usize>, // coin.id
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GossipData {
    // updates source and, optionally, a target with state. Should not clobber newer state.
    epoch: usize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TrimData {
    coins: Vec<Coin>, // World updates; Agent self-trims
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UpdateEpochData {
    revoked: usize, // Agent id.
}

// Must mirror AgentRoles
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RequestRole {
    Consumer,
    Merchant,
    Bank,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RequestTransactionData {
    amount: usize,
    epoch: usize, // Since we can't see it during apply.
    role: RequestRole,
}

// Any event with World as a destination is a world event.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum EventData {
    // Agents
    Age(usize),
    Register(RegisterData),
    Synchronize(SynchronizeData), // Grant tickets in here.
    Validate(ValidateData),
    ValidateResponse(ValidateResponseData), // Returns bad coins
    Transact(TransactData),
    RejectedTransact,
    Gossip(GossipData),
    RequestTransaction(RequestTransactionData),
    Move(Location),
    Trim(TrimData),
    // World/Operator
    UpdateEpoch(UpdateEpochData),
    UpdateStatistics(Statistics),
    // TODO: CoinSwap(CoinSwapData), // And max history len
    // TODO: To allow bank/online merchant/etc discovery, query for the agent, a descriptor, its epoch so the recipient can queue cross-view/cell transactions.
    // ----
    // TODO: QueryAgents(QueryAgentsData)
    // TODO: QueryAgentsResponse(QARData)
    // Population
    Arrive(PopulationAdd),
    Depart(PopulationDel),
    // Don't see any need for extra enum layers.
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum SupportedDistributions {
    Uniform,
    Pareto,
    Levy,
}
impl Default for SupportedDistributions {
    fn default() -> Self {
        SupportedDistributions::Uniform
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GridCell {
    agents: Vec<usize>,
    resources: Vec<usize>,
}

impl GridCell {
    pub fn new() -> GridCell {
        GridCell {
            agents: Vec::new(),
            resources: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Grid<T> {
    bounds: (usize, usize),
    cells: Vec<T>,
}

impl Grid<GridCell> {
    pub fn new(bounds: (usize, usize)) -> Grid<GridCell> {
        Grid {
            bounds: bounds,
            cells: vec![GridCell::new(); bounds.0 * bounds.1],
        }
    }
    pub fn reset(&mut self) {
        self.cells = vec![GridCell::new(); self.bounds.0 * self.bounds.1];
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Default)]
pub struct Location(usize, usize);
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Default)]
pub struct Offset(isize, isize);

pub trait GridIndex<U> {
    fn at_location_mut(&mut self, l: Location) -> &mut U;
    fn at_location(&self, l: Location) -> &U;

    fn get_index(&self, l: Location) -> usize;
    fn get_location<T: Into<usize>>(&self, index: T) -> Location;
}

impl<U> GridIndex<U> for Grid<U> {
    fn at_location_mut(&mut self, l: Location) -> &mut U {
        let i = self.get_index(l);
        &mut self.cells[i]
    }
    fn at_location(&self, l: Location) -> &U {
        let i = self.get_index(l);
        &self.cells[i]
    }
    fn get_index(&self, l: Location) -> usize {
        let Location(x_u64, y_u64) = l;
        let x: usize = x_u64.try_into().unwrap();
        let y: usize = y_u64.try_into().unwrap();
        let w: usize = self.bounds.0.try_into().unwrap();
        w * y + x
    }
    fn get_location<T: Into<usize>>(&self, index: T) -> Location {
        let w: usize = self.bounds.0.try_into().unwrap();
        let i: usize = index.try_into().unwrap();
        Location(
            (i % w).try_into().unwrap(),
            ((i - (i % w)) / w).try_into().unwrap(),
        )
    }
}

impl Enqueue<Simulator> for Vec<Event<EventData>> {
    fn enqueue(&mut self, source: Address<usize>, target: Address<usize>, data: EventData) {
        self.push(Event {
            id: self.len(),
            source,
            target,
            data,
        });
    }
}

#[derive(Clone, Debug)]
pub struct Rngs {
    uniform: Box<rand::rngs::StdRng>,
    pareto: Box<rand::rngs::StdRng>,
    levy: Box<rand::rngs::StdRng>,
}
impl Rngs {
    pub fn new(rng_conf: &RngConfiguration) -> Rngs {
        Rngs {
            uniform: Box::new(SeedableRng::seed_from_u64(rng_conf.seed)),
            pareto: Box::new(SeedableRng::seed_from_u64(rng_conf.seed)),
            levy: Box::new(SeedableRng::seed_from_u64(rng_conf.seed)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Distributions {
    levy: Box<levy_distr::Levy<f64>>,
    pareto: Box<rand_distr::Pareto<f64>>,
    uniform: Box<rand_distr::Uniform<f64>>,
}
impl Distributions {
    pub fn new(rng_conf: &RngConfiguration) -> Distributions {
        Distributions {
            levy: Box::new(Levy::<f64>::new(rng_conf.levy_min_step, rng_conf.levy_alpha).unwrap()),
            pareto: Box::new(Pareto::new(rng_conf.pareto_scale, rng_conf.pareto_shape).unwrap()),
            uniform: Box::new(Uniform::new::<f64, f64>(0., rng_conf.uniform_max)),
        }
    }
}

pub struct RngContext {
    rngs: Rngs,
    distributions: Distributions,
}
impl RngContext {
    pub fn new(rng_conf: &RngConfiguration) -> RngContext {
        RngContext {
            rngs: Rngs::new(&rng_conf),
            distributions: Distributions::new(&rng_conf),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Flights {
    levy: Flight<rand::rngs::StdRng, levy_distr::Levy<f64>, u64, 2>,
    pareto: Flight<rand::rngs::StdRng, rand_distr::Pareto<f64>, u64, 2>,
    uniform: Flight<rand::rngs::StdRng, rand_distr::Uniform<f64>, u64, 2>,
}

impl Flights {
    pub fn new(bounds: &[usize; 2], ctx: Box<RngContext>) -> Flights {
        Flights {
            uniform: Flight::<StdRng, Uniform<f64>, u64, 2>::new(
                ctx.rngs.uniform,
                ctx.distributions.uniform,
                [bounds[0].try_into().unwrap(), bounds[1].try_into().unwrap()],
            )
            .unwrap(),
            pareto: Flight::<StdRng, Pareto<f64>, u64, 2>::new(
                ctx.rngs.pareto,
                ctx.distributions.pareto,
                [bounds[0].try_into().unwrap(), bounds[1].try_into().unwrap()],
            )
            .unwrap(),
            levy: Flight::<StdRng, Levy<f64>, u64, 2>::new(
                ctx.rngs.levy,
                ctx.distributions.levy,
                [bounds[0].try_into().unwrap(), bounds[1].try_into().unwrap()],
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimulatorHelpers {
    rng: Box<rand::rngs::StdRng>,
    distributions: Distributions,
    flights: Flights,
}
impl SimulatorHelpers {
    pub fn new(bounds: (usize, usize), rng_config: &RngConfiguration) -> SimulatorHelpers {
        // Setup all the rngs
        let flight_ctx = Box::new(RngContext::new(&rng_config));
        // TODO: Separate configs!
        // Create FlightRng and RngConfig
        let mut rcfg = rng_config.clone();
        rcfg.uniform_max = 1.0;
        let rng_context = Box::new(RngContext::new(&rcfg));
        SimulatorHelpers {
            rng: rng_context.rngs.uniform,
            distributions: Distributions {
                levy: rng_context.distributions.levy,
                pareto: rng_context.distributions.pareto,
                uniform: rng_context.distributions.uniform,
            },
            flights: Flights::new(&[bounds.0, bounds.1], flight_ctx),
        }
    }
}
pub trait SimulationTools {
    fn probability_check(&mut self, distribution: &SupportedDistributions, threshold: f64) -> bool;
    fn get_uniform(&mut self, base: usize, max: usize) -> usize;
    fn relocate(&mut self, distribution: &SupportedDistributions, source: &Location) -> Location;
}

impl SimulationTools for SimulatorHelpers {
    fn relocate(&mut self, distribution: &SupportedDistributions, source: &Location) -> Location {
        let src: [u64; 2] = [source.0.try_into().unwrap(), source.1.try_into().unwrap()];
        let mut dst: [u64; 2] = [0, 0];
        match distribution {
            SupportedDistributions::Levy => {
                self.flights.levy.step(&src, &mut dst);
            }
            SupportedDistributions::Uniform => {
                self.flights.uniform.step(&src, &mut dst);
            }
            SupportedDistributions::Pareto => {
                self.flights.pareto.step(&src, &mut dst);
            }
        }
        Location(dst[0].try_into().unwrap(), dst[1].try_into().unwrap())
    }
    fn get_uniform(&mut self, base: usize, max: usize) -> usize {
        if max <= base {
            eprintln!("get_uniform: base >= max");
            return 0;
        }
        let range = Uniform::from(base..max);
        range.sample(&mut self.rng)
    }

    fn probability_check(&mut self, distribution: &SupportedDistributions, threshold: f64) -> bool {
        match distribution {
            SupportedDistributions::Uniform => {
                self.distributions.uniform.sample(&mut self.rng) <= threshold
            }
            SupportedDistributions::Pareto => {
                self.distributions.pareto.sample(&mut self.rng) <= threshold
            }
            SupportedDistributions::Levy => {
                self.distributions.levy.sample(&mut self.rng) <= threshold
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RngConfiguration {
    seed: u64,
    levy_min_step: f64,
    levy_alpha: f64,
    pareto_scale: f64,
    pareto_shape: f64,
    uniform_max: f64,
}

impl RngConfiguration {
    pub fn new(
        seed: u64,
        levy_min_step: f64,
        levy_alpha: f64,
        pareto_scale: f64,
        pareto_shape: f64,
        uniform_max: f64,
    ) -> Self {
        RngConfiguration {
            seed,
            levy_min_step,
            levy_alpha,
            pareto_scale,
            pareto_shape,
            uniform_max,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorldData {
    // World
    step: usize, // GlobalTick event
    bounds: (usize, usize),
    grid: Grid<GridCell>,
    resources: Vec<ResourceData>,
    statistics: Statistics,
    // Operator data
    epoch: usize, // current epoch
    epochs: Vec<SyncState>,
    last_coin_index: usize,              // for minting
    coin_map: HashMap<usize, CoinState>, // for keeping historical data view
    banks: Vec<usize>,                   // List of bank ids
    pending: Vec<Event<EventData>>,      // Events which should be fired off in the next gen phase
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ViewData {
    id: usize,
    step: usize, // GlobalTick event
    bounds: (usize, usize),
    resource: ResourceData, // Just one for now.
    // We could copy WorldData here, but it seems less messy to just copy what we need.
    epoch: usize,
    epochs: Vec<SyncState>,
}

impl Simulation for Simulator {
    type Data = AgentData;
    type Event = EventData;
    type World = WorldData;
    type View = ViewData;
    type SimulationPopulation = SimulationPopulation<Self>;
    type ViewPopulation = SimulationPopulation<Self>;

    fn worldview(
        &self,
        id: usize,
        population: &Self::SimulationPopulation,
        world: &Self::World,
    ) -> Option<WorldView<Self>> {
        if id >= world.grid.cells.len() {
            return None;
        }
        let location = world.grid.get_location(id);
        let cell = world.grid.at_location(location.clone());
        /*
        println!(
            "Generating cellular World View: ({}, {})",
            location.0, location.1
        );
        */
        // Create our own population copy.
        let mut pop = Box::new(SimulationPopulation::new());
        for id in &cell.agents {
            // Keep same ids
            pop.update(&population.get(id.clone()).unwrap().clone());
        }
        let mut resource = ResourceData::default();
        if cell.resources.len() > 0 {
            resource = world.resources[cell.resources[0]].clone();
        }
        // TODO: Don't copy all epochs over time, but still more efficient than putting it in each
        // agent.
        Some(WorldView::new(
            pop,
            ViewData {
                id: id,
                step: world.step,
                bounds: world.bounds,
                resource: resource,
                epoch: world.epoch,
                epochs: world.epochs.clone(),
            },
        ))
    }

    fn generate(
        &self,
        agent: &Agent<Self::Data>,
        view: &WorldView<Self>,
        queue: &mut EventQueue<Self>,
    ) -> usize {
        let mut count = 0;
        let helper = &mut *self.helper.write().expect("interior mutability");
        let mut stats = Statistics::default();

        for e in &agent.data.pending {
            queue.enqueue(e.source, e.target, e.data.clone());
            count += 1;
        }
        queue.enqueue(
            Address::NoAddress,
            Address::AgentId(agent.id),
            EventData::Age(view.data().step),
        );
        count += 1;

        match &agent.data.role {
            // Generate bank events
            AgentRole::Bank(_data) => {
                // Syncs every tick even if it doesnt validate every tick.
                queue.enqueue(
                    Address::AgentId(agent.id),
                    Address::World,
                    EventData::Synchronize(SynchronizeData {}),
                );
                count += 1;
            }
            //
            AgentRole::Merchant(data) => {
                if let Some(_tx_step) = data.last_tx_step {
                    // TODO: Make deposit timeframe configurable
                    // Deposit 4 times a day.
                    if view.data().step % 8 == 0 {
                        // Construct a dummy bank so we can reuse do_transaction()
                        let mut bank = Agent {
                            id: data.bank,
                            data: AgentData::default(),
                        };
                        // Bank is always up-to-date.
                        // For other "online" we'll need to RequestInfo to get the recipient's epoch. Or enforce a Sync before online.
                        bank.data.epoch = view.data().epoch;
                        bank.data.role = AgentRole::Bank(BankData::default());
                        // Currently, amount is just # of coins.
                        // let amount = agent.data.coins.iter().map(|c| c.value).sum();
                        let amount = agent.data.coins.len();
                        let mut coin_count = 0;
                        // TODO: Enable deposit double spend attempts too, etc.
                        if amount > 0 {
                            count += self.do_transaction(
                                &view.data(),
                                helper,
                                agent,
                                &bank,
                                amount,
                                false,
                                false,
                                &mut coin_count,
                                queue,
                            );
                        }
                    }
                }
            }
            // Generate consumer events
            AgentRole::Consumer(data) => {
                // Required before any other work.
                if agent.data.registered == false {
                    // Later enables hwids to be added, etc and double spenders to be filtered?
                    queue.enqueue(
                        Address::AgentId(agent.id),
                        Address::World,
                        EventData::Register(RegisterData {}),
                    );
                    count += 1;
                    return count;
                }
                if helper.probability_check(&data.sync_distribution, data.sync_probability)
                    || data.wids < data.wid_low_watermark
                {
                    // Later enables hwids to be added, etc.
                    queue.enqueue(
                        Address::AgentId(agent.id),
                        Address::World,
                        EventData::Synchronize(SynchronizeData {}),
                    );
                    count += 1;
                }
                // TODO Add low threshold for withdrawl and other models like withdraw-on-demand!
                if agent.data.coins.len() < 2
                    && data.account_balance > 5
                    && view.data().step > data.last_requested_step + 1
                {
                    // TODO: We should enqueue a Gossip here but we'll let the bank fire it off.
                    queue.enqueue(
                        Address::AgentId(agent.id),
                        Address::AgentId(data.bank),
                        EventData::RequestTransaction(RequestTransactionData {
                            amount: min(data.account_balance, 5),
                            epoch: agent.data.epoch,
                            role: RequestRole::Consumer,
                        }),
                    );
                    // println!("[Agent {}] My bank is {} and my coins are {} and my balance is {}", agent.id, data.bank, agent.data.coins.len(), data.account_balance);
                    count += 1;
                }
                // If the consumer can and wants to transact.
                // TODO: Add support for _multiple_ transaction per-step, like at a hawker market
                // Add support for peer and merchant in same step.
                // E.g., avail_wids = wids; avail_coins = coins.len();
                // while cnt < per_period && avail_wids > 0 && avail_coins > 0 ...
                if agent.data.registered && agent.data.coins.len() > 0 && data.wids > 0 {
                    let mut peer = None;
                    if helper.probability_check(&data.p2m_distribution, data.p2m_probability) {
                        let merchant_iter = view.population().agents.iter().filter(|entry| {
                            match entry.1.data.role {
                                AgentRole::Merchant(_) => true,
                                _ => false,
                            }
                        });
                        if let Some(merchant_entry) = merchant_iter.choose(&mut helper.rng) {
                            // println!("Picked a merchant to transact with! {}", merchant_entry.0);
                            peer = view.population().agents.get(merchant_entry.0);
                        }
                    } else if helper.probability_check(&data.p2p_distribution, data.p2p_probability)
                    {
                        let peer_iter =
                            view.population().agents.iter().filter(|entry| {
                                match entry.1.data.role {
                                    AgentRole::Consumer(_) => true,
                                    _ => false,
                                }
                            });
                        if let Some(peer_entry) = peer_iter.choose(&mut helper.rng) {
                            // println!("Picked a peer to transact with! {}", peer_entry.0);
                            peer = view.population().agents.get(peer_entry.0);
                        }
                    }
                    if let Some(receiver) = peer {
                        // Will we double spend?
                        let ds = data.double_spend_probability > 0.0
                            && helper.probability_check(
                                &data.double_spend_distribution,
                                data.double_spend_probability,
                            );
                        // Gossip & transact
                        // TODO: Add transaction count enforcement per step period.
                        // Note: rng doesn't like it is the range is 0 (e.g., 1, 1).
                        // Also, if multiple txns are allowed per-step, the max can't be the coin
                        // list.
                        let amount = max(1, helper.rng.gen_range(0..agent.data.coins.len()));
                        let mut coin_count = 0;
                        count += self.do_transaction(
                            &view.data(),
                            helper,
                            agent,
                            receiver,
                            amount,
                            ds,
                            false,
                            &mut coin_count,
                            queue,
                        );
                    }
                }
                if helper.probability_check(&data.move_distribution, data.move_probability) {
                    let new_location =
                        helper.relocate(&data.move_distribution, &agent.data.location);
                    // TODO: Figure out if we can get rid of the crawl without incurring worse overhead.
                    queue.enqueue(
                        Address::AgentId(agent.id),
                        Address::NoAddress,
                        //Address::View(view.id), // Tells the world what cell we were in without looking it up.
                        EventData::Move(new_location),
                    );
                    count += 1;
                }
            }
        }
        if stats != Statistics::default() {
            queue.enqueue(
                Address::AgentId(agent.id),
                Address::World,
                EventData::UpdateStatistics(stats),
            );
        }
        count + 1
    }

    fn apply(
        &self,
        agent: &mut Agent<Self::Data>,
        world: &Self::World,
        event: &Event<Self::Event>,
    ) {
        let helper = &mut *self.helper.write().expect("interior mutability");
        let mut stats = Statistics::default();
        // Since generate() cannot delete the pending events, clear the queue if it has old events
        // in it.
        if let Some(e) = agent.data.pending.iter().last() {
            if world.step > e.id {
                agent.data.pending.clear();
            }
        }
        // TODO add log levels
        // println!("agent {}: {:?}", agent.id, event);

        // Handle common event paths
        match &event.data {
            EventData::Gossip(gdata) => {
                // TODO: figure out how to count how long it took to reach world.epoch.
                let old = agent.data.epoch;
                agent.data.epoch = max(gdata.epoch, agent.data.epoch);
                // Double spenders don't actually update.
                if let AgentRole::Consumer(cdata) = &agent.data.role {
                    if cdata.double_spend_probability != 0.0 {
                        agent.data.epoch = old;
                    }
                }
            }
            EventData::Synchronize(_) => {
                if agent.data.epoch < world.epoch {
                    agent.data.epoch = world.epoch;
                }
            }
            EventData::Transact(txn) => {
                // If money is sent to an agent, they should:
                // 1. Check if the recipient is revoked and reject it (done in generate()!)
                // 2. Optionally queue up a Validate() call depending on their needs (TODO: see below)
                // 3. Add the coins to their coin list! (done)
                if event.target == Address::AgentId(agent.id) {
                    for tcoin in &txn.coins {
                        // Not common, but banks put money in holding first.
                        let mut coin = tcoin.coin.clone();
                        // The simulation knows this is a copy even if the operator doesn't yet.
                        if tcoin.copy {
                            coin.copied = true;
                            // Increment counterfeits total
                            stats.coins_double_spent_total += 1;
                            // Increment total coins in circulation, including counterfeits.
                            stats.coins_total += 1;
                        }
                        if let AgentRole::Bank(bank) = &mut agent.data.role {
                            bank.holding.push(coin);
                        } else {
                            agent.data.coins.push(coin);
                        }
                    }
                }
                // If money is sent by an agent, they must only remove it if it wasn't double spent.
                if event.source == Address::AgentId(agent.id) {
                    // For every coin we sent, remove it from our wallet.
                    // Assume the txn coins will never be _huge_ vs a potential bank coin list.
                    let mut removals = txn
                        .coins
                        .iter()
                        .filter_map(|c| {
                            if c.copy == false && c.popped == false {
                                Some(c.coin.clone())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<Coin>>();
                    // Keep track so we can stop early since we always takes from the tail.
                    let mut index = agent.data.coins.len();
                    while removals.len() > 0 {
                        index -= 1;
                        let coin = &agent.data.coins[index];
                        // Make sure we remove the exact match since double spending may result in
                        // duplicate IDs. In that case, we remove an unseen coin and make this agent look
                        // like a double spender.
                        if let Some(r) = removals.iter().position(|c| {
                            coin.id == c.id
                                && coin.tx_history[..(c.tx_history.len() - 1)]
                                    == c.tx_history[..(c.tx_history.len() - 1)]
                        }) {
                            agent.data.coins.swap_remove(index);
                            removals.swap_remove(r);
                        }
                        // We can always decrement because swap_remove() will pull the last element, which we will have already processed.
                        if index == 0 {
                            break;
                        }
                    }
                    assert!(removals.len() == 0);
                }
            }
            _ => {}
        }

        match &mut agent.data.role {
            AgentRole::Bank(data) => {
                match &event.data {
                    EventData::ValidateResponse(resp_data) => {
                        if event.target == Address::AgentId(agent.id) {
                            // Move ok coins out (_once_) and destroy bad coins.
                            // TODO: Request new coins from operator to replace bad coins.
                            let mut lists = resp_data.clone();
                            let mut index = 0;
                            while index < data.holding.len() {
                                let id = data.holding[index].id;
                                if let Some(position) =
                                    lists.counterfeit.iter().position(|c| *c == id)
                                {
                                    data.holding.swap_remove(index);
                                    lists.counterfeit.swap_remove(position);
                                    println!(
                                        "[agent {}] bank destroying bad coin {}",
                                        agent.id, id
                                    );
                                } else if let Some(position) =
                                    lists.ok.iter().position(|c| *c == id)
                                {
                                    agent.data.coins.push(data.holding.swap_remove(index));
                                    lists.ok.swap_remove(position);
                                } else {
                                    index += 1;
                                }
                            }
                        }
                    }
                    EventData::RequestTransaction(rt_data) => {
                        // A consumer is requesting funds which they should only request if they have
                        // the balance... but balance and coins may not match.
                        if event.target == Address::AgentId(agent.id) {
                            if let Address::AgentId(source) = event.source {
                                // Construct a dummy agent so we can reuse do_transaction()
                                let mut target_data: AgentData = AgentData::default();
                                match rt_data.role {
                                    RequestRole::Merchant => {
                                        target_data.role =
                                            AgentRole::Merchant(MerchantData::default())
                                    }
                                    RequestRole::Bank => {
                                        target_data.role = AgentRole::Bank(BankData::default())
                                    }
                                    _ => {} // Consumer is the default.
                                }
                                target_data.epoch = rt_data.epoch;
                                let target = Agent {
                                    id: source,
                                    data: target_data,
                                };
                                // TODO: Should apply() also just get a pre-fab ViewData that matches the agent's ViewData on generate()?
                                let view_data = ViewData {
                                    id: 0,
                                    step: world.step,
                                    bounds: world.bounds,
                                    resource: ResourceData::default(),
                                    epoch: world.epoch,
                                    epochs: world.epochs.clone(),
                                };
                                let mut pending = Vec::new();
                                // WE must delete the coins or mark them as spent otherwise we'll double
                                // spend and search oru whole list for coins we don't have.
                                let mut pop_count = 0;
                                self.do_transaction(
                                    &view_data,
                                    helper,
                                    agent,
                                    &target,
                                    rt_data.amount,
                                    false,
                                    true,
                                    &mut pop_count,
                                    &mut pending,
                                );
                                agent.data.pending.append(&mut pending);
                                for _p in 0..pop_count {
                                    agent.data.coins.pop();
                                }
                                // Tag the last event so we don't drain this on a repeat call.
                                // Hacky but why waste yet another variable... :)
                                if let Some(e) = agent.data.pending.iter_mut().last() {
                                    e.id = world.step;
                                }
                            }
                        }
                    }
                    EventData::Transact(txn) => {
                        // The common code above should do all normal checks.
                        // Here we should enqueue a Validate(), etc.
                        // If we're the source, the coins were removed when we created the transaction
                        // above -- so there's no work.
                        // If we're the destination, add the coins to our reserves.
                        if event.target == Address::AgentId(agent.id) {
                            let mut new_coins = Vec::new();
                            for tcoin in &txn.coins {
                                new_coins.push(tcoin.coin.clone());
                            }
                            // We dont want to validate every coin in the bank every time, so queue up a
                            // validate for any deposit.
                            let validate_data = ValidateData { coins: new_coins };
                            agent.data.pending.push(Event {
                                id: world.step,
                                source: Address::AgentId(agent.id),
                                target: Address::World,
                                data: EventData::Validate(validate_data),
                            });
                        }
                    }
                    _ => {}
                }
            }
            AgentRole::Consumer(data) => {
                match &event.data {
                    EventData::Move(loc) => {
                        // Only move if we're the source
                        if let Address::AgentId(id) = event.source {
                            if id == agent.id {
                                agent.data.location = loc.clone();
                            }
                        }
                    }
                    EventData::Register(_) => {
                        // TODO: Add revoked-logic here since a double spender will have exposed
                        // their HWID which makes their device revocable permanently -- stopping them
                        // from re-registering.
                        agent.data.registered = true;
                    }
                    EventData::Synchronize(_) => {
                        // WIDs are issued blindly but it is known how many have been issued to a
                        // given linkable-proof/signature that is not linkable in other contexts.
                        // This enables WID issuance to be total limited per time. Here we just only
                        // ever top up to 8, but we shoud move to tracking time quanta totals per
                        // linked-sig.
                        // TODO: Discuss this more deeply.
                        // TODO: Swap with a GrantTickets event if world mutation is needed.
                        if data.wids < 8 {
                            // TODO: Operator determined.
                            data.wids = 8;
                        }
                    }
                    EventData::RequestTransaction(rt_data) => {
                        // If we withdrew money, decrement our balance
                        // and be patient for a step.
                        if event.source == Address::AgentId(agent.id)
                            && event.target == Address::AgentId(data.bank)
                        {
                            data.account_balance -= rt_data.amount;
                            data.last_requested_step = world.step;
                        }
                    }
                    EventData::Transact(_txn) => {
                        if event.source == Address::AgentId(agent.id) {
                            // Now decrement the WID unless the agent is a double spender
                            if stats.coins_double_spent_total == 0 {
                                // this event has not double spent.
                                data.wids -= 1;
                            }
                        }
                        // TODO: add support for deposit if over a wallet threshold.
                    }
                    EventData::RejectedTransact => {
                        if data.max_rejections > 0 {
                            data.max_rejections -= 1;
                        }
                        if data.max_rejections == 0 {
                            agent.data.pending.push(Event {
                                id: world.step,
                                source: Address::AgentId(agent.id),
                                target: Address::Population,
                                data: EventData::Depart(PopulationDel {
                                    ids: vec![agent.id],
                                }),
                            });
                        }
                    }
                    EventData::Age(_call_step) => {
                        data.lifetime -= 1;
                        if data.lifetime == 0 {
                            agent.data.pending.push(Event {
                                id: world.step,
                                source: Address::AgentId(agent.id),
                                target: Address::Population,
                                data: EventData::Depart(PopulationDel {
                                    ids: vec![agent.id],
                                }),
                            });
                        }
                    }
                    _ => {}
                }
            }
            AgentRole::Merchant(data) => match &event.data {
                EventData::Transact(_txn) => {
                    if event.target == Address::AgentId(agent.id) {
                        data.last_tx_step = Some(world.step);
                    }
                }
                EventData::Age(_call_step) => {
                    data.lifetime -= 1;
                    if data.lifetime == 0 {
                        agent.data.pending.push(Event {
                            id: world.step,
                            source: Address::AgentId(agent.id),
                            target: Address::Population,
                            data: EventData::Depart(PopulationDel {
                                ids: vec![agent.id],
                            }),
                        });
                    }
                }
                _ => {}
            },
        }
        if stats != Statistics::default() {
            agent.data.pending.push(Event {
                id: world.step,
                source: Address::AgentId(agent.id),
                target: Address::World,
                data: EventData::UpdateStatistics(stats),
            });
        }
    }

    // Perform distribution/consumption events from the current cell resources.
    fn view_generate(&self, _view: &WorldView<Self>, _queue: &mut EventQueue<Self>) -> usize {
        0
    }

    fn world_generate(
        &self,
        _population: &Self::SimulationPopulation,
        world: &Self::World,
        queue: &mut EventQueue<Self>,
    ) -> usize {
        // enqueue GlobalTick to Address::All if we want to allow singular event generation.
        /*
        queue.enqueue(
                    Address::World,
                    Address::NoAddress,
                    EventData::World(Tick),
                );
        */
        // TODO: Every n events, mint money
        // TODO: Every n events, update bank account balances.
        let mut count = 0;
        for e in &world.pending {
            queue.enqueue(e.source, e.target, e.data.clone());
            count += 1;
        }
        count
    }

    fn world_apply(
        &self,
        world: &mut Self::World,
        population: &Self::SimulationPopulation,
        events: &Vec<Event<Self::Event>>,
    ) {
        // Unlike agents, world_apply is called once per-tick.
        world.step += 1;
        world.pending.clear();

        // Update the grid here
        // First agents, then resources.
        //println!("Applying world events: {:?}", events);
        world.grid.reset();
        // Update world view
        for agent in population.agents.values() {
            world
                .grid
                .at_location_mut(agent.data.location.clone())
                .agents
                .push(agent.id);
        }
        for r in 0..world.resources.len() {
            let resource = &world.resources[r];
            world
                .grid
                .at_location_mut(resource.location.clone())
                .resources
                .push(r); // index == id
        }

        // Handle operator events now.
        for event in events {
            match &event.data {
                EventData::UpdateEpoch(_ue_data) => todo!(),
                EventData::Register(_) => {
                    world.statistics.register_total += 1;
                }
                EventData::Synchronize(_) => {
                    world.statistics.synchronize_total += 1;
                }
                EventData::UpdateStatistics(stats) => {
                    world.statistics.update(&stats);
                }
                EventData::Validate(vdata) => {
                    //println!("Validate: {:?}", event);
                    world.statistics.validate_total += 1;
                    let mut bad_coins = vec![];
                    let mut good_coins = vec![];
                    for coin in &vdata.coins {
                        if world.coin_map.contains_key(&coin.id) {
                            let known_coin_state = world.coin_map.get_mut(&coin.id).unwrap();
                            // If we already know this coin is bad, just collect the stats and move on.
                            if let Some(step) = known_coin_state.revoked {
                                bad_coins.push(coin.id);
                                // For this, we have to compute the different between the fork point and the history.
                                if let Some(txn_fork) = known_coin_state.fork_txn {
                                    // If a double spent coin is validated against the last known good history, then it shows up here because its
                                    // been revoked even though it will not have a txn_fork entry to consume.  We will push a 0 for that instead since
                                    // that is the reserved tx_history for minting.
                                    let coin_tx;
                                    if coin.tx_history.len() > txn_fork + 1 {
                                        coin_tx = coin.tx_history[txn_fork + 1];
                                        world.statistics.double_spent_most_txns = max(
                                            world.statistics.double_spent_most_txns,
                                            coin.history.len() - txn_fork,
                                        );
                                    } else {
                                        // To show we've now seen an untransferred bad coin.
                                        // TODO: Should we track if the double spender themselves checks in? Later, yes.
                                        // -> This might be how malware abused devices can be shown recoverable.
                                        // -> Need a innocent double spender profile where all their money is transferred away and they only spend bad coins.
                                        // -> Then see if we can catch the actual abuser because they will have received coins from the caught ds. (No HWID, so it'd be trace based.)
                                        // TODO: Add a system trace based on coin/coins to see how it looks as money moves.
                                        coin_tx = 0;
                                    }
                                    // Ignore already seen coins.
                                    if known_coin_state.forks.contains(&coin_tx) {
                                        // We've already seen this double spend path.
                                        // TODO: later note when the same bad coin is resubmitted as it shows the validator didn't delete it.
                                        world.statistics.coins_double_spent_recovered_repeats += 1;
                                        // Skip since we've seen it before.
                                        continue;
                                    } else {
                                        world.statistics.coins_double_spent_recovered += 1;
                                        known_coin_state.forks.push(coin_tx);
                                    }

                                    assert!(txn_fork <= coin.history.len());
                                    println!(
                                  "[operator] recovered double spend of coin {} (forked by Agent {}) after {} txns and {} steps",
                                  coin.id, coin.history[txn_fork], coin.history.len() - txn_fork, world.step - step
                              );
                                }
                                // in steps, not transfers. Transfers we can get from the history.
                                world.statistics.double_spent_longest_life = max(
                                    world.statistics.double_spent_longest_life,
                                    world.step - step,
                                );

                                continue;
                            }
                            let known_coin = &known_coin_state.coin;
                            // Now we see if the history is shorter or forked.
                            // If the coin coming in has a shorter history, it's a fork.
                            // If the history matches, then we can update.
                            let mut ds = None;
                            let mut ds_entry = None;
                            if coin.history.len() < known_coin.history.len() {
                                assert!(coin.history[0] == known_coin.history[0]);
                                assert!(coin.history.len() == coin.tx_history.len());
                                for entry in 1..coin.history.len() {
                                    if coin.history[entry] != known_coin.history[entry]
                                        || coin.tx_history[entry] != known_coin.tx_history[entry]
                                    {
                                        ds = Some(coin.history[entry - 1]);
                                        ds_entry = Some(entry - 1);
                                        break;
                                    }
                                }
                            } else {
                                assert!(coin.history[0] == known_coin.history[0]);
                                assert!(coin.history.len() == coin.tx_history.len());
                                for entry in 1..known_coin.history.len() {
                                    if coin.history[entry] != known_coin.history[entry]
                                        || coin.tx_history[entry] != known_coin.tx_history[entry]
                                    {
                                        ds = Some(coin.history[entry - 1]);
                                        ds_entry = Some(entry - 1);
                                        break;
                                    }
                                }
                            }
                            if let Some(ds_agent) = ds {
                                bad_coins.push(coin.id);
                                // Revoke the coin in our state map.
                                if let Some(entry) = ds_entry {
                                    known_coin_state.revoked = Some(coin.step_history[entry]);
                                    known_coin_state.fork_txn = Some(entry);
                                    known_coin_state.forks.push(coin.tx_history[entry + 1]);
                                }

                                // Create revocation sync data and update global state.
                                if world.epochs[world.epoch].revocation.contains(&ds_agent) == false
                                {
                                    println!(
                                    "[operator] double spending by agent {} detected. Revoking . . .",
                                    ds_agent
                                );
                                    println!("Coin: {:?}", coin);
                                    println!("Known coin: {:?}", known_coin);
                                    let last_step = world.epochs[world.epoch].step;
                                    let last_revocation =
                                        world.epochs[world.epoch].revocation.clone();
                                    // Add to an existing SyncState if the step hasn't changed.
                                    if last_step != world.step {
                                        world.epoch += 1;
                                        // TODO: Add revocation where everyone in a group is quarantined and cannot
                                        //       transact without a fresh registration and then filter the double spender
                                        //       out for human handling since we learned their hwid during DS.  This should allow
                                        //       device recovery and not depend on wid expiry to DS enforcement.
                                        //       Essentially "group" revocation.
                                        world.epochs.push(SyncState {
                                            id: world.epoch,
                                            revocation: last_revocation,
                                            quarantine: Vec::new(),
                                            step: world.step,
                                        });
                                    }
                                    world.epochs[world.epoch].revocation.push(ds_agent);

                                    world.statistics.double_spenders_revoked_total += 1;
                                }

                                // Validate doesnt happen on Sync.
                                // In Sync, we can't recover or see coins unless that is
                                // _required_. E.g., show what you have to get more wids? That
                                // seems risky for tracking.
                                world.statistics.coins_double_spent_recovered += 1;
                                // Now remove the coin from the Updater
                                // TODO: Add counter to hash map.
                                let survived_txns = coin.history.len() - ds_entry.unwrap();
                                // Start from the first transfer
                                let survived_steps =
                                    world.step - coin.step_history[ds_entry.unwrap() + 1];
                                println!(
                                "[operator] recovered double spend of coin {} after {} txns and {} steps",
                                coin.id, survived_txns, survived_steps,
                            );
                                /*
                                  println!("New {:?}", coin.history);
                                  println!("New {:?}", coin.tx_history);
                                  println!("Known {:?}", known_coin.history);
                                  println!("Known {:?}", known_coin.tx_history);
                                */
                                // Don't insert the bogus history.
                                continue;
                            } else {
                                // Often, the first double spend creates the first legitimate history entry.
                                // if coin.copied {
                                //  println!("We didn't detect foul play with a copied coin. First entry? {:?}", coin);
                                //}
                            }
                        }
                        // Update the history if the coin is good.
                        world.coin_map.insert(coin.id, CoinState::new(coin.clone()));
                        good_coins.push(coin.id);
                    }
                    let resp_data = ValidateResponseData {
                        ok: good_coins,
                        counterfeit: bad_coins,
                    };
                    world.pending.push(Event {
                        id: world.step,
                        source: Address::World,
                        target: event.source,
                        data: EventData::ValidateResponse(resp_data),
                    });
                }
                EventData::ValidateResponse(_resp_data) => {}
                _ => todo!(),
            }
        }
    }
    fn population_apply(
        &self,
        population: &mut Self::SimulationPopulation,
        _world: &Self::World,
        events: &Vec<Event<Self::Event>>,
    ) {
        // TODO log levels
        // println!("population: {:?}", events);
        for event in events {
            match &event.data {
                EventData::Arrive(add_data) => {
                    // TODO: loglevels println!("Adding {} agents and resources", add_data.count);
                    population.new_agents(&add_data.data, add_data.count);
                }
                // TODO clean up Depart
                EventData::Depart(del_data) => {
                    for id in &del_data.ids {
                        println!("[agent {}] is departing", id);
                        population.remove(id);
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct NetworkData {
    online_probability: f64,
    online_distribution: SupportedDistributions,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct AgentConfiguration {
    class: AgentRole,
    count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResourceClass {
    Network(NetworkData),
}
impl Default for ResourceClass {
    fn default() -> Self {
        ResourceClass::Network(NetworkData::default())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct ResourceConfiguration {
    class: ResourceClass,
    count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Configuration {
    rng_configuration: RngConfiguration,
    //display_configuration: DisplayConfiguration,
    bounds: (usize, usize),
    num_steps: usize,

    agents: Vec<AgentConfiguration>,
    resources: Vec<ResourceConfiguration>,
    // TODO(wad) Add online grid region mapping.
    // TODO(wad) Add merchant grid region mapping.
}

impl Configuration {
    pub fn from_file(path: &String) -> Configuration {
        let file_content = fs::read_to_string(path).expect("GridSim: error reading configuration");
        serde_json::from_str::<Configuration>(&file_content)
            .expect("GridSim: failed to parse configuration file")
        /*
        print!(
            "{}",
            serde_json::to_string_pretty(&payload).expect("GridSim: error printing cfg")
        );
        */
    }
}

fn main() {
    // Use configured seed as root to spawn off all rngs.
    let mut rng: StdRng = SeedableRng::seed_from_u64(99);
    let mgr_seed = rng.gen::<u64>();
    // NYC 29,729/sqmil;  300.6 sq mi= 17.33*17.33
    // Let's aim smaller.  10*10 = 100, so 2972900
    // Let's aim smaller.  3 * 3 = 9 so 297290
    let bounds = (8, 8);
    let helper = SimulatorHelpers::new(
        bounds.clone(),
        &RngConfiguration::new(mgr_seed, 3.0, 1.8, 2.0, 2.0, 20.0),
    );

    let num_consumers = 5000; //237832; // 2972900; // Full NYC pop 18867000; // 139; // 10000;  // Scaled NYC pop
    let num_double_spenders = (num_consumers / 2000) + 1;
    let num_merchants = (num_consumers / 115) + 1;
    let num_banks = (num_consumers / 77000) + 1;

    // Setup init stats
    let mut upstats = Statistics::default();

    let default_balance = 500;
    // Create enough coinage for every consumer to have $20 in the bank to get started.
    let mut coinage = Vec::new();
    // Use a map so we can remove these easily before we simulate.
    let mut bank_coins: HashMap<usize, Vec<Coin>> = HashMap::new();
    let mut coin_index = 0;
    for c in 0..(num_consumers * default_balance) {
        let b = c % num_banks;
        coinage.push(Coin {
            id: coin_index,
            value: 1,
            copied: false,
            history: vec![usize::MAX, b], // mint is usize::MAX
            tx_history: vec![0, 1],       // Don't need randomness since this is controlled.
            step_history: vec![0, 0],
        });
        if let Some(treasury) = bank_coins.get_mut(&b) {
            treasury.push(coinage.iter().last().unwrap().clone());
        } else {
            bank_coins.insert(b, vec![coinage.iter().last().unwrap().clone()]);
        }
        coin_index += 1;
    }
    upstats.coins_total = coinage.len();
    upstats.coins_valid_total = coinage.len();

    let mut mgr = Manager::new(
        Simulator::new(mgr_seed, helper),
        SimulationPopulation::new(),
        WorldData {
            step: 0,
            bounds: bounds.clone(),
            grid: Grid::<GridCell>::new(bounds),
            resources: vec![],
            statistics: Statistics::default(),
            // Operator init
            epoch: 0,
            epochs: vec![SyncState::default()],
            last_coin_index: coin_index,
            coin_map: coinage
                .into_iter()
                .enumerate()
                .map(|(i, v)| (i, CoinState::new(v)))
                .collect(),
            banks: (0..num_banks).collect(), // Add banks first. TODO: track then via Register() later.
            pending: vec![],
        },
    );
    //print!("Manager: {}", serde_json::to_string_pretty(&mgr).unwrap());
    for _ in 0..4 {
        let client_seed = rng.gen::<u64>();
        mgr.add_client(Box::new(LocalSimulationClient::new(Simulator::new(
            client_seed,
            SimulatorHelpers::new(
                bounds.clone(),
                &RngConfiguration::new(client_seed, 3.0, 1.8, 2.0, 2.0, 20.0),
            ),
        ))));
    }
    // Create a few banks and expect their IDs to be 0..num_banks
    for b in 0..num_banks {
        let x = rng.gen_range(0..mgr.world().bounds.0);
        let y = rng.gen_range(0..mgr.world().bounds.1);
        mgr.enqueue(
            Address::NoAddress,
            Address::Population,
            vec![EventData::Arrive(PopulationAdd {
                data: AgentData {
                    location: Location(x, y),
                    registered: true,
                    epoch: 0,
                    coins: bank_coins.remove(&b).unwrap(),
                    pending: vec![],
                    role: AgentRole::Bank(BankData { holding: vec![] }),
                },
                count: 1,
            })],
        );
    }

    // Randomly place 10k consumers
    for c in 0..num_consumers {
        let x = rng.gen_range(0..mgr.world().bounds.0);
        let y = rng.gen_range(0..mgr.world().bounds.1);
        mgr.enqueue(
            Address::NoAddress,
            Address::Population,
            vec![EventData::Arrive(PopulationAdd {
                data: AgentData {
                    location: Location(x, y),
                    registered: false,
                    epoch: 0,
                    coins: vec![],
                    pending: vec![],
                    role: AgentRole::Consumer(ConsumerData {
                        lifetime: 43800, // 5 years in hours for phone lifetime.
                        sync_probability: 0.01,
                        sync_distribution: SupportedDistributions::Uniform,
                        p2m_probability: 0.8,
                        p2m_distribution: SupportedDistributions::Uniform,
                        p2p_probability: 0.1,
                        p2p_distribution: SupportedDistributions::Uniform,
                        double_spend_probability: 0.0,
                        double_spend_distribution: SupportedDistributions::Uniform,
                        max_rejections: 5,
                        move_distribution: SupportedDistributions::Uniform,
                        move_probability: 0.9,
                        /*(
                        step_period: 24,
                        max_transactions_per_period: 2,
                        */
                        wids: 8,
                        wid_low_watermark: 2,
                        account_balance: default_balance,
                        last_requested_step: 0,
                        bank: c % num_banks, // ensure we match the balance with the coins. TODO: Register() to get bank and balance.
                    }),
                },
                count: 1,
            })],
        );
    }

    // Randomly place double spenders
    for _ in 0..num_double_spenders {
        let x = rng.gen_range(0..mgr.world().bounds.0);
        let y = rng.gen_range(0..mgr.world().bounds.1);
        mgr.enqueue(
            Address::NoAddress,
            Address::Population,
            vec![EventData::Arrive(PopulationAdd {
                data: AgentData {
                    location: Location(x, y),
                    registered: false,
                    epoch: 0,
                    coins: vec![],
                    pending: vec![],
                    role: AgentRole::Consumer(ConsumerData {
                        lifetime: 43800, // 5 years in hours for phone lifetime.
                        sync_probability: 0.0,
                        sync_distribution: SupportedDistributions::Uniform,
                        p2m_probability: 1.0,
                        p2m_distribution: SupportedDistributions::Uniform,
                        p2p_probability: 1.0,
                        p2p_distribution: SupportedDistributions::Uniform,
                        double_spend_probability: 1.0,
                        double_spend_distribution: SupportedDistributions::Uniform,
                        max_rejections: 5,
                        move_distribution: SupportedDistributions::Uniform,
                        move_probability: 1.0,
                        /*
                        step_period: 24,
                        max_transactions_per_period: 72,
                        */
                        wids: 8,
                        wid_low_watermark: 2,
                        account_balance: default_balance,
                        last_requested_step: 0,
                        bank: rng.gen_range(0..num_banks),
                    }),
                },
                count: 1,
            })],
        );
    }

    // Randomly place double spenders in the future
    for _ in 0..num_double_spenders {
        let x = rng.gen_range(0..mgr.world().bounds.0);
        let y = rng.gen_range(0..mgr.world().bounds.1);
        mgr.enqueue_delayed(
            Address::NoAddress,
            Address::Population,
            vec![EventData::Arrive(PopulationAdd {
                data: AgentData {
                    location: Location(x, y),
                    registered: false,
                    epoch: 0,
                    coins: vec![],
                    pending: vec![],
                    role: AgentRole::Consumer(ConsumerData {
                        lifetime: 43800, // 5 years in hours for phone lifetime.
                        sync_probability: 0.0,
                        sync_distribution: SupportedDistributions::Uniform,
                        p2m_probability: 1.0,
                        p2m_distribution: SupportedDistributions::Uniform,
                        p2p_probability: 1.0,
                        p2p_distribution: SupportedDistributions::Uniform,
                        double_spend_probability: 1.0,
                        double_spend_distribution: SupportedDistributions::Uniform,
                        max_rejections: 5,
                        move_distribution: SupportedDistributions::Uniform,
                        move_probability: 1.0,
                        /*
                        step_period: 24,
                        max_transactions_per_period: 72,
                        */
                        wids: 8,
                        wid_low_watermark: 2,
                        account_balance: default_balance,
                        last_requested_step: 0,
                        bank: rng.gen_range(0..num_banks),
                    }),
                },
                count: 1,
            })],
            40,
        );
    }

    upstats.double_spenders_total = num_double_spenders * 2;
    // Update the states
    mgr.enqueue(
        Address::NoAddress,
        Address::World,
        vec![EventData::UpdateStatistics(upstats)],
    );

    // Randomly place consumers/115 merchants
    for _ in 0..num_merchants {
        let x = rng.gen_range(0..(mgr.world().bounds.0));
        let y = rng.gen_range(0..(mgr.world().bounds.1));
        mgr.enqueue(
            Address::NoAddress,
            Address::Population,
            vec![EventData::Arrive(PopulationAdd {
                data: AgentData {
                    location: Location(x, y),
                    registered: false,
                    epoch: 0,
                    coins: vec![],
                    pending: vec![],
                    role: AgentRole::Merchant(MerchantData {
                        lifetime: 183960, // 21 years in hours -- avg lifespan of company S&P.
                        sync_probability: 0.01,
                        sync_distribution: SupportedDistributions::Uniform,
                        account_balance: 0,
                        last_tx_step: None,
                        bank: rng.gen_range(0..num_banks),
                    }),
                },
                count: 1,
            })],
        );
    }

    // Install network probability in every grid point.
    for x in 0..bounds.0 {
        for y in 0..bounds.1 {
            mgr.world().resources.push(ResourceData {
                location: Location(x, y),
                class: ResourceClass::Network(NetworkData {
                    online_probability: 0.8,
                    online_distribution: SupportedDistributions::Uniform,
                }),
            });
        }
    }

    mgr.register_observer(1, &observe);
    mgr.run(10000);
}

fn observe(step: usize, world: &WorldData, _pop: &SimulationPopulation<Simulator>) {
    println!(
        "[{}] --------------------------------------------------------------------",
        step
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&world.statistics).unwrap()
    );
    /*
    let num_con = pop
        .agents
        .iter()
        .filter(|agt| match agt.1.data.role {
            AgentRole::Consumer(_) => true,
            _ => false,
        })
        .count();
    let num_mer = pop
        .agents
        .iter()
        .filter(|agt| match agt.1.data.role {
            AgentRole::Merchant(_) => true,
            _ => false,
        })
        .count();
    println!("[{}] consumers: {} merchants: {}", step, num_con, num_mer);
    */
}
