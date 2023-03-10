// Copyright 2022 Google, LLC
//
// Type design is heavily inspired by https://github.com/frnsys/djinn

// Expose default implementations
pub mod clients;
pub mod extras;

use rand::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Range;

pub trait SimulationData: Serialize + DeserializeOwned + Send + Sync + Clone {}
impl<T> SimulationData for T where T: DeserializeOwned + Serialize + Send + Sync + Clone {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(bound = "SD: SimulationData")]
pub struct Agent<SD: SimulationData> {
    pub id: usize,
    pub data: SD,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Address<T> {
    NoAddress,
    AgentId(T),
    View(T),
    World,
    Population,
}

impl<T> Address<T> {
    pub fn is_agent(&self) -> bool {
        match self {
            Address::NoAddress => false,
            Address::World => false,
            Address::AgentId(_) => true,
            Address::View(_) => false,
            Address::Population => false,
        }
    }
    pub fn is_view(&self) -> bool {
        match self {
            Address::NoAddress => false,
            Address::World => false,
            Address::AgentId(_) => false,
            Address::View(_) => true,
            Address::Population => false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(bound = "ED: SimulationData")]
pub struct Event<ED: SimulationData> {
    pub id: usize,
    pub source: Address<usize>,
    pub target: Address<usize>,
    pub data: ED,
}

use std::fmt;

#[derive(Debug)]
pub enum PopulationError {
    InvalidAgentId,
}

impl std::error::Error for PopulationError {}

impl fmt::Display for PopulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PopulationError::InvalidAgentId => write!(f, "Invalid Agent ID"),
        }
    }
}

pub trait Population<S: Simulation>: Serialize + DeserializeOwned + Send + Sync + Clone {
    fn new_agents(&mut self, data: &S::Data, num: usize);
    fn update(&mut self, agent: &Agent<S::Data>);
    // Proxies SliceRandom::choose
    fn choose<R>(&self, rng: &mut R) -> Option<&Agent<S::Data>>
    where
        R: Rng + ?Sized;
    fn get(&self, id: usize) -> Result<&Agent<S::Data>, PopulationError>;
    fn get_many(&self, id_range: Range<usize>) -> Vec<Agent<S::Data>>;
    fn get_mut(&mut self, id: usize) -> Result<&mut Agent<S::Data>, PopulationError>;
    fn len(&self) -> usize;
    // TODO move to iter
    fn for_each(&self, c: &dyn Fn(&Agent<S::Data>) -> ());
    fn for_each_mut(&mut self, c: &dyn Fn(&mut Agent<S::Data>) -> ());
    fn remove(&mut self, id: &usize);
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventQueue<S: Simulation> {
    agent: Vec<Event<S::Event>>, //FnvHashMap<usize, Vec<(u64, S::Event)>>,
    world: Vec<Event<S::Event>>,
    population: Vec<Event<S::Event>>,
}

pub trait Enqueue<S: Simulation>: Sized + Send + Sync + Clone {
    fn enqueue(&mut self, source: Address<usize>, target: Address<usize>, data: S::Event);
}

impl<S: Simulation> Enqueue<S> for EventQueue<S> {
    fn enqueue(&mut self, source: Address<usize>, target: Address<usize>, data: S::Event) {
        if source.is_agent() || target.is_agent() {
            let id = self.agent.len();
            /* Log level!
            println!(
                "enqueuing from {} to {}",
                serde_json::to_string_pretty(&source).unwrap(),
                serde_json::to_string_pretty(&target).unwrap()
            );
            */
            self.agent.push(Event {
                id,
                source: source.clone(),
                target: target.clone(),
                data: data.clone(),
            });
        }
        if source == Address::World || target == Address::World {
            let id = self.world.len();
            self.world.push(Event {
                id,
                source: source.clone(),
                target: target.clone(),
                data: data.clone(),
            });
        }
        if source == Address::Population || target == Address::Population {
            let id = self.world.len();
            self.population.push(Event {
                id,
                source: source.clone(),
                target: target.clone(),
                data: data.clone(),
            });
        }
        if source.is_view() || target.is_view() {
            let id = self.world.len();
            self.world.push(Event {
                id,
                source: source.clone(),
                target: target.clone(),
                data: data.clone(),
            });
        }
    }
}

impl<S: Simulation> EventQueue<S> {
    pub fn new() -> Self {
        Self {
            agent: Vec::new(),
            world: Vec::new(),
            population: Vec::new(),
        }
    }
    pub fn clear(&mut self) {
        self.agent.clear();
        self.world.clear();
        self.population.clear();
    }
    pub fn agent_mut(&mut self) -> &mut Vec<Event<S::Event>> {
        &mut self.agent
    }
    pub fn world_mut(&mut self) -> &mut Vec<Event<S::Event>> {
        &mut self.world
    }
    pub fn population_mut(&mut self) -> &mut Vec<Event<S::Event>> {
        &mut self.population
    }

    pub fn append(&mut self, source: &mut EventQueue<S>) {
        self.agent.append(&mut source.agent_mut());
        self.world.append(&mut source.world_mut());
        self.population.append(&mut source.population_mut());
    }
}

// Defines the WorldView any given agent will see when generating or applying.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorldView<S: Simulation> {
    population: Box<S::ViewPopulation>,
    data: S::View,
}

impl<S: Simulation> WorldView<S> {
    pub fn new(population: Box<S::ViewPopulation>, data: S::View) -> Self {
        Self { population, data }
    }
    pub fn population(&self) -> &S::ViewPopulation {
        return &self.population;
    }
    pub fn data(&self) -> &S::View {
        return &self.data;
    }
}

// Simulator should have Population? Or does manager call in with it?
// Is
pub trait Simulation: Sized + Send + Sync + Clone {
    type Data: SimulationData;
    type Event: SimulationData;
    // World is the global view.
    // Agents often lack global access, so we give them a regional view.
    type World: SimulationData;
    type View: SimulationData;
    type SimulationPopulation: Population<Self>;
    type ViewPopulation: Population<Self>; // TODO: move to struct with .iter

    // Based on an incrementing id, emit a WorldView or None.
    fn worldview(
        &self,
        _id: usize,
        _population: &Self::SimulationPopulation,
        _world: &Self::World,
    ) -> Option<WorldView<Self>> {
        None
    }

    // For workers, do we not transmit world but instead rebuild world from transmitted resources and agents?
    // World is global data and grid
    fn generate(
        &self,
        _agent: &Agent<Self::Data>,
        _view: &WorldView<Self>,
        _queue: &mut EventQueue<Self>,
    ) -> usize {
        0
    }
    fn apply(
        &self,
        _agent: &mut Agent<Self::Data>,
        _world: &Self::World,
        _events: &Event<Self::Event>,
    ) {
    }

    fn view_generate(&self, _view: &WorldView<Self>, _queue: &mut EventQueue<Self>) -> usize {
        0
    }

    fn world_generate(
        &self,
        _population: &Self::SimulationPopulation,
        _world: &Self::World,
        _queue: &mut EventQueue<Self>,
    ) -> usize {
        0
    }
    fn world_apply(
        &self,
        _world: &mut Self::World,
        _population: &Self::SimulationPopulation,
        _events: &Vec<Event<Self::Event>>,
    ) {
    }
    fn population_apply(
        &self,
        _population: &mut Self::SimulationPopulation,
        _world: &Self::World,
        _events: &Vec<Event<Self::Event>>,
    ) {
    }
}

/// Provides a standard client interface
///
pub trait SimulationClient<S: Simulation>: Send {
    fn run(&mut self, step: usize, view: &WorldView<S>);
    fn collect(&mut self, queue: &mut EventQueue<S>);
}

// Fn(n_steps,&
pub trait ManagerObserver<S: Simulation>:
    Fn(usize, &S::World, &S::SimulationPopulation) -> () + Send + 'static
{
}
impl<S: Simulation, T> ManagerObserver<S> for T where
    T: Fn(usize, &S::World, &S::SimulationPopulation) -> () + Send + 'static
{
}

struct Observer<S: Simulation> {
    steps: usize,
    cb: Box<dyn ManagerObserver<S>>,
}

pub trait ManagerInterface<S: Simulation> {
    fn add_client(&mut self, client: Box<dyn SimulationClient<S>>);
    fn enqueue(&mut self, source: Address<usize>, target: Address<usize>, data: Vec<S::Event>);
    fn enqueue_delayed(
        &mut self,
        source: Address<usize>,
        target: Address<usize>,
        data: Vec<S::Event>,
        delay: usize,
    );
    fn world(&mut self) -> &mut S::World;
    fn run(&mut self, max_steps: usize);
    fn register_observer<O>(&mut self, steps: usize, cb: O)
    where
        O: ManagerObserver<S> + 'static;
}

pub struct Manager<S: Simulation> {
    population: S::SimulationPopulation,
    simulator: S,
    world: S::World,
    clients: Vec<Box<dyn SimulationClient<S>>>,
    queue: EventQueue<S>,
    delay_queue: HashMap<usize, EventQueue<S>>,
    observers: Vec<Observer<S>>,
}

impl<S: Simulation> ManagerInterface<S> for Manager<S> {
    fn add_client(&mut self, client: Box<dyn SimulationClient<S>>) {
        /* Simulator config needs to follow */
        self.clients.push(client);
    }
    fn enqueue(&mut self, source: Address<usize>, target: Address<usize>, data: Vec<S::Event>) {
        for datum in data {
            self.queue.enqueue(source.clone(), target.clone(), datum);
        }
    }
    fn enqueue_delayed(
        &mut self,
        source: Address<usize>,
        target: Address<usize>,
        data: Vec<S::Event>,
        delay: usize,
    ) {
        if self.delay_queue.contains_key(&delay) == false {
            self.delay_queue.insert(delay, EventQueue::new());
        }
        let mut queue = self.delay_queue.get_mut(&delay).unwrap();
        for datum in data {
            queue.enqueue(source.clone(), target.clone(), datum);
        }
    }

    fn world(&mut self) -> &mut S::World {
        &mut self.world
    }
    fn run(&mut self, max_steps: usize) {
        let client_count = self.clients.len();
        let mut queue = EventQueue::new();
        for s in 0..max_steps {
            let mut active_client = 0;
            let mut view_id = 0;
            // Pull in any manager interface events.
            queue.append(&mut self.queue);
            self.queue.clear();
            // Pull in scheduled events.
            // TODO: Determine if agents can schedule.
            if self.delay_queue.contains_key(&s) {
                queue.append(self.delay_queue.get_mut(&s).unwrap());
                self.delay_queue.remove(&s);
            }

            while let Some(view) = self
                .simulator
                .worldview(view_id, &self.population, &self.world)
            {
                // Farm out regions to client
                // This MUST be deterministic or it breaks replay.
                active_client = (active_client + 1) % client_count;
                let client = &mut self.clients[active_client];
                client.run(s, &view); // Clients ONLY generate, never apply.
                view_id += 1;
            }
            for client in &mut self.clients {
                client.collect(&mut queue);
            }
            // Add any new world events.
            self.simulator
                .world_generate(&self.population, &self.world, &mut queue);
            // Now per-agent distribution.
            // Agents are called multiple times per-tick. We could solve that
            // with a hashmap, but a Tick() event would work well and allow flexible scheduling.
            for eid in 0..queue.agent.len() {
                let event = &queue.agent[eid];
                if let Address::AgentId(src_id) = event.source {
                    if let Ok(agent) = self.population.get_mut(src_id) {
                        self.simulator.apply(agent, &self.world, &event);
                    } else {
                        eprintln!("Invalid agent requested: {}", src_id);
                    }
                }
                if let Address::AgentId(tgt_id) = event.target {
                    if let Ok(agent) = self.population.get_mut(tgt_id) {
                        self.simulator.apply(agent, &self.world, &event);
                    } else {
                        eprintln!("Invalid agent requested: {}", tgt_id);
                    }
                }
            }

            // Process any population events
            self.simulator.population_apply(
                &mut self.population,
                &self.world,
                &mut queue.population,
            );

            // We should now have a queue full of events for this step.
            // World applies last to allow location updates, etc.
            self.simulator
                .world_apply(&mut self.world, &self.population, &queue.world);

            // Clear for the next step.
            queue.clear();
            for observer in &self.observers {
                if s % observer.steps == 0 {
                    let cb = &observer.cb;
                    cb(s, &self.world, &self.population);
                }
            }
        }
    }
    fn register_observer<O>(&mut self, steps: usize, cb: O)
    where
        O: ManagerObserver<S> + 'static,
    {
        self.observers.push(Observer {
            steps,
            cb: Box::new(cb),
        });
    }
}

impl<S: Simulation> Manager<S> {
    pub fn new(simulator: S, population: S::SimulationPopulation, world: S::World) -> Self {
        Self {
            population,
            simulator,
            world,
            queue: EventQueue::new(),
            delay_queue: HashMap::new(),
            clients: vec![],
            observers: vec![],
        }
    }
}
