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

// Stub code

use rand::{rngs::StdRng, SeedableRng};
use rand_distr::Uniform;
use rand_flight::{Flight, Step};

fn main() {
    let rng = Box::new(SeedableRng::seed_from_u64(1));
    let dist = Box::new(Uniform::new::<f64, f64>(0., 20.));
    let mut lf = Flight::<StdRng, Uniform<f64>, u64, 2>::new(rng, dist, &[200, 200]).unwrap();

    // Show a sequence with at least one large jump and many small
    // moves to help validate the shift to 2d.
    let mut result = [0, 0];
    let mut start = [100, 100];
    lf.step(&start, &mut result);
    //println!("{:indent$}({},{})", ".", start[0], start[1], indent=start[0] as usize);
    println!("{},{}:eventX,eventY", start[0], start[1]);
    for step in 1..100 {
        lf.step(&start, &mut result);
        start = result;
        //println!("{:indent$}({},{})", ".", start[0], start[1], indent=start[0] as usize);
        println!("{}:{},{}:eventX,eventY", step, start[0], start[1]);
    }
}
