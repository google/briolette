// Copyright 2022 Google
// Stub code
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

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
