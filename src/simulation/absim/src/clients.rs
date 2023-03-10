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

use crate::{EventQueue, Population, Simulation, SimulationClient, WorldView};
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;


//#[derive(Clone)]
pub struct LocalSimulationClient<S: Simulation> {
    step: usize,
    queue: Arc<RwLock<EventQueue<S>>>,
    simulator: S,
    handles: Vec<thread::JoinHandle<()>>,
}
impl<S: Simulation + 'static> SimulationClient<S> for LocalSimulationClient<S> {
    fn run(&mut self, step: usize, view: &WorldView<S>) {
       if self.step != step {
           if self.queue.read().unwrap().agent.len() != 0 {
               eprintln!("[{}] Agent queue non-zero from step {}", step, self.step);
           }
           if self.handles.len() > 0 {
               while self.handles.len() > 0 {
                 let h = self.handles.remove(0);
                 h.join();
               }
           }
            self.queue.write().unwrap().clear();
            self.step = step;
       }
       let thread_view = view.clone();
       // This introduces variability in the RNG state.
       // We should seed once per step
       // The simulator clone must handle this.
       let simulator = self.simulator.clone();
       let queue = self.queue.clone();
       self.handles.push(thread::spawn(move||{
        simulator.view_generate(&thread_view, &mut queue.write().unwrap());
        //  println!("[{}] view::generate added events [world queue: {}]", step, queue.read().unwrap().world.len());
        thread_view.population.for_each(&|agent|  {
            simulator.generate(agent, &thread_view, &mut queue.write().unwrap());
        });
        // TODO log levels 
        //println!("[{}] agent::generate added events [agent queue: {}]", step, queue.read().unwrap().agent.len());
      }));
    }
    fn collect(&mut self, queue: &mut EventQueue<S>) {
           if self.handles.len() > 0 {
               // println!("Collect called after {} threads", self.handles.len());
               while self.handles.len() > 0 {
                 let h = self.handles.remove(0);
                 h.join();
               }
           }
      queue.append(&mut self.queue.write().unwrap());
      self.queue.write().unwrap().clear();
    }
}

impl<S: Simulation> LocalSimulationClient<S> {
    pub fn new(simulator: S /*, rng_config */) -> Self {
        Self {
            step: 0,
            queue: Arc::new(RwLock::new(EventQueue::new())), // shared event queue.
            simulator: simulator,  // root simulator for clones in threads.
            handles: vec![], // thread handles, per step.
        }
    }

}
