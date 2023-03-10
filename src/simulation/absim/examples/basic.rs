// Copyright 2022 Google, LLC
//
// Provides a simple case to exercise simulation features.
use rand::prelude::*;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use absim::clients::LocalSimulationClient;
use absim::extras::SimulationPopulation;
use absim::{
    Address, Agent, Enqueue, Event, EventQueue, Manager, ManagerInterface, Population, Simulation, WorldView,
};

#[derive(Debug)]
pub struct Simulator {
    pub seed: u64,
    pub clones: Arc<RwLock<usize>>, // Interior Mutability
    pub rng: Arc<RwLock<StdRng>>, // Interior Mutability!
}
impl Simulator {
    pub fn new(seed: u64) -> Self {
      Self {
          seed: seed,
          clones: Arc::new(RwLock::new(0)),
          rng: Arc::new(RwLock::new(SeedableRng::seed_from_u64(seed))),
      }
    }
}
// Create a stable way to maintained seeded randomness across view and client splits.
impl Clone for Simulator {
  fn clone(&self) -> Self {
      let mut c = self.clones.write().unwrap();
      *c += 1;
      let m: u64 = (*c).try_into().unwrap();
      // TODO: overflow will happen :)
      Self {
          seed: self.seed,
          clones: Arc::new(RwLock::new(*c)),
          rng: Arc::new(RwLock::new(SeedableRng::seed_from_u64(self.seed + m))),
      }
  }
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct EntityData {
    location: Location,
    calories: usize,
    alive: bool,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum AgentData {
    Entity(EntityData),
    Resource(ResourceData),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct ResourceData {
    location: Location,
    food: usize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct WorldEvent {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum EntityEvent {
    Move(Offset), // burns calories
    Eat(usize),
    Plant(Location),
    Birth,
    Die,
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
#[serde(rename_all = "lowercase")]
pub enum PopulationEvent {
    Add(PopulationAdd),
    Del(PopulationDel),
}

// Any event with World as a destination is a world event.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum EventData {
    World(WorldEvent),
    Entity(EntityEvent),
    Population(PopulationEvent),
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct Location(usize, usize);
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct WorldData {
    // World
    step: usize, // GlobalTick event
    bounds: (usize, usize),
    grid: Grid<GridCell>,
    resources: Vec<ResourceData>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ViewData {
    id: usize,
    step: usize, // GlobalTick event
    bounds: (usize, usize),
    resource: ResourceData, // Just one for now.
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
        let mut resource = ResourceData {
            location: location,
            food: 0,
        };
        if cell.resources.len() > 0 {
            resource = world.resources[cell.resources[0]].clone();
        }
        // Adds some ghost agents that are local resources from the grid.
        // They never do an apply - we just let world do that.
        // This ensures atomic push of resources and any agent decision
        // has to go in the resource area.

        Some(WorldView::new(
            pop,
            ViewData {
                id: id,
                step: world.step,
                bounds: world.bounds,
                resource: resource,
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
        let rng = &mut *self.rng.write().expect("interior mutability");
        if let AgentData::Entity(entity) = &agent.data {
            if entity.alive == false {
                return 0;
            }
            if entity.calories > 60 {
                queue.enqueue(
                    Address::AgentId(agent.id),
                    Address::NoAddress, // Could go right to Population
                    EventData::Entity(EntityEvent::Birth),
                );
                queue.enqueue(
                    Address::NoAddress,
                    Address::Population,
                    EventData::Population(PopulationEvent::Add(PopulationAdd {
                        data: AgentData::Entity(EntityData {
                            location: entity.location.clone(),
                            calories: 27,
                            alive: true,
                        }),
                        count: 1,
                    })),
                );
                count += 2;
            }
            if entity.calories == 0 {
                // set entity.alive = 0
                queue.enqueue(
                    Address::AgentId(agent.id),
                    Address::World,
                    EventData::Entity(EntityEvent::Die),
                );
                count += 1;
                queue.enqueue(
                    Address::AgentId(agent.id),
                    Address::Population,
                    EventData::Population(PopulationEvent::Del(PopulationDel {
                    ids: vec![agent.id]
                })));
                count += 1;
                return count;
            }
            // Plant food
            if rng.gen::<f32>() < 0.21943 {
                queue.enqueue(
                    Address::AgentId(agent.id),
                    Address::World,
                    EventData::Entity(EntityEvent::Plant(entity.location)),
                );
                count += 1;
            }
            // Move up to 3 spaces x or y.
            let x = (-3..3).choose(rng).unwrap();
            let y = (-3..3).choose(rng).unwrap();
            queue.enqueue(
                Address::AgentId(agent.id),
                Address::NoAddress, // World can crawl after apply to update
                EventData::Entity(EntityEvent::Move(Offset(x, y))),
            );
            count += 1;
        }
        count
    }
    fn apply(
        &self,
        agent: &mut Agent<Self::Data>,
        world: &Self::World,
        event: &Event<Self::Event>,
    ) {
        // TODO add log levels
        // println!("agent {}: {:?}", agent.id, event);
        match &mut agent.data {
            AgentData::Entity(entity) => {
                if entity.alive == false {
                    return;
                }
                match &event.data {
                    EventData::Entity(data) => match data {
                        EntityEvent::Eat(amt) => {
                            entity.calories += amt;
                        }
                        EntityEvent::Move(offset) => {
                            if entity.calories >= 6 {
                                entity.calories -= 6;
                                // Relative move
                                let mut x: isize = entity.location.0.try_into().unwrap();
                                let mut y: isize = entity.location.1.try_into().unwrap();
                                x += offset.0;
                                y += offset.1;
                                if x < 0 {
                                    x = 0;
                                }
                                if y < 0 {
                                    y = 0;
                                }
                                if x >= world.bounds.0.try_into().unwrap() {
                                    x = world.bounds.0.try_into().unwrap();
                                    x -= 1;
                                }
                                if y >= world.bounds.1.try_into().unwrap() {
                                    y = world.bounds.1.try_into().unwrap();
                                    y -= 1;
                                }
                                entity.location =
                                    Location(x.try_into().unwrap(), y.try_into().unwrap());
                            } else {
                                entity.calories = 0;
                            }
                        }
                        EntityEvent::Birth => {
                            if entity.calories > 60 {
                                entity.calories -= 60;
                            } else {
                                entity.calories = 0;
                            }
                        }
                        EntityEvent::Die => {
                            // log level println!("Entity {} died!", agent.id);
                            entity.alive = false;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            _ => todo!(),
        }
    }

    // Perform consumption events from the current cell.
    fn view_generate(&self, view: &WorldView<Self>, queue: &mut EventQueue<Self>) -> usize {
        let mut count = 0;
        let rng = &mut *self.rng.write().expect("interior mutability");
        // Feed random agents until all the food is gone.
        let mut food = view.data().resource.food;
        let mut amt = 6; // one moves
        while food > 0 && view.population().len() > 0 {
            let recipient = view.population().choose(rng);
            /* TODO: log levels
            println!(
                "view population count {}, {:?}",
                view.population().count(),
                recipient
            );
            */
            if recipient == None {
                continue;
            }
            match &recipient.unwrap().data {
                AgentData::Entity(ed) => {
                    if ed.alive == false {
                        continue;
                    }
                }
                _ => {}
            }
            if food < amt {
                amt = food;
            }
            food -= amt;

            queue.enqueue(
                Address::View(view.data().id), // update grid resources
                Address::AgentId(recipient.unwrap().id),
                EventData::Entity(EntityEvent::Eat(amt)),
            );
            count += 1;
        }
        count
    }

    fn world_generate(
        &self,
        _population: &Self::SimulationPopulation,
        _world: &Self::World,
        _queue: &mut EventQueue<Self>,
    ) -> usize {
        // enqueue GlobalTick
        /*
        queue.enqueue(
                    Address::World,
                    Address::NoAddress,
                    EventData::World(Tick),
                );
        */
        0
    }
    fn world_apply(
        &self,
        world: &mut Self::World,
        population: &Self::SimulationPopulation,
        events: &Vec<Event<Self::Event>>,
    ) {
        // First agents, then resources.
        //println!("Applying world events: {:?}", events);
        world.grid.reset();
        // TODO: need iter.
        for agent in population.agents.values() {
            if let AgentData::Entity(entity) = &agent.data {
                if entity.alive {
                    world
                        .grid
                        .at_location_mut(entity.location.clone())
                        .agents
                        .push(agent.id);
                }
            }
        }
        for r in 0..world.resources.len() {
            let resource = &world.resources[r];
            world
                .grid
                .at_location_mut(resource.location.clone())
                .resources
                .push(r); // index == id
        }

        // Unlike agents, world_apply is called once per-tick.
        // Update the grid here
        // Process resource changes here rather than tracking a second agent pool.
        for event in events {
            match &event.data {
                EventData::Entity(data) => match data {
                    EntityEvent::Eat(amt) => {
                        if let Address::View(id) = event.source {
                            let cell = world.grid.at_location(world.grid.get_location(id));
                            let mut resource = &mut world.resources[cell.resources[0]];
                            if amt >= &resource.food {
                                resource.food = 0;
                            }
                            if amt < &resource.food {
                                resource.food -= amt;
                            }
                        }
                    }
                    EntityEvent::Plant(location) => {
                        let cell = world.grid.at_location(location.clone());
                        let mut resource = &mut world.resources[cell.resources[0]];
                        resource.food += 36;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
    fn population_apply(
        &self,
        population: &mut Self::SimulationPopulation,
        world: &Self::World,
        events: &Vec<Event<Self::Event>>,
    ) {
        // TODO log levels
        // println!("population: {:?}", events);
        for event in events {
            match &event.data {
                EventData::Population(pe) => match pe {
                    PopulationEvent::Add(add_data) => {
                        // TODO: loglevels println!("Adding {} agents and resources", add_data.count);
                        for _ in 0..add_data.count {
                            let rng = &mut *self.rng.write().expect("interior mutability");
                            let x = rng.gen_range(0..world.bounds.0);
                            let y = rng.gen_range(0..world.bounds.1);
                            match &add_data.data {
                                AgentData::Entity(edata) => {
                                    population.new_agents(
                                        &AgentData::Entity(EntityData {
                                            location: Location(x, y),
                                            calories: edata.calories,
                                            alive: edata.alive,
                                        }),
                                        1,
                                    );
                                }
                                _ => population.new_agents(&add_data.data, 1),
                            }
                        }
                        // TODO use world data to set locations, etc.
                    }
                    PopulationEvent::Del(del_data) => for id in &del_data.ids { population.remove(id); }
                },
                _ => {}
            }
        }
    }
}

fn main() {
    // Use configured seed as root to spawn off all rngs.
    let mut rng: StdRng = SeedableRng::seed_from_u64(99);
    let mgr_seed = rng.gen::<u64>();
    println!("mgr seed: {}", mgr_seed);
    let bounds = (20, 20);
    let mut mgr = Manager::new(
        Simulator::new(mgr_seed),
        SimulationPopulation::new(),
        WorldData {
            step: 0,
            bounds: bounds.clone(),
            grid: Grid::<GridCell>::new(bounds),
            resources: vec![],
        },
    );
    //print!("Manager: {}", serde_json::to_string_pretty(&mgr).unwrap());
    for c in 0..10 {
        let client_seed = rng.gen::<u64>();
        println!("client {} seed: {}", c, client_seed);
        mgr.add_client(Box::new(LocalSimulationClient::new(Simulator::new(client_seed))));
    }
    // Enqueue some initial events to get it going!
    for _ in 0..1000 {
        let x = rng.gen_range(0..mgr.world().bounds.0);
        let y = rng.gen_range(0..mgr.world().bounds.1);
        mgr.enqueue(
            Address::NoAddress,
            Address::Population,
            vec![EventData::Population(PopulationEvent::Add(PopulationAdd {
                data: AgentData::Entity(EntityData {
                    location: Location(x, y),
                    calories: 12,
                    alive: true,
                }),
                count: 1,
            }))],
        );
    }
    // Add resources so our entities can eat

    for x in 0..bounds.0 {
        for y in 0..bounds.1 {
            mgr.world().resources.push(ResourceData {
                location: Location(x, y),
                food: 36,
            });
        }
    }
// TODO add_
    mgr.register_observer(10, &observe);
    mgr.run(10000);
}

fn observe(step: usize, world: &WorldData, pop: &SimulationPopulation<Simulator>) {
    let alive = pop
        .agents.len();
    let dead = pop.next_id - pop.agents.len();
    let res_total: usize = world.resources.iter().map(|r| r.food).sum();

    println!(
        "[{}] alive: {} dead: {} food: {} ",
        step, alive, dead, res_total
    );
}
