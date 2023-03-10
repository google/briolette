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

// Random Flight Generator

use core::fmt;
use rand::Rng;
use rand_distr::Distribution;

// Flights cover arbitrary ground in a single step.
// All flights occur over `D' axes starting at 0 ending at `bounds'.
// For integer types, steps are quantized. For float types, they are not.
#[derive(Clone, Debug)]
pub struct Flight<R, RD, T, const D: usize>
where
    R: rand::RngCore,
    RD: Distribution<f64>,
{
    rng: Box<R>,
    distribution: Box<RD>,
    bounds: [T; D],
}

/// Error type returned from `Flight::new`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `dimensions > 1`
    DimensionsTooLarge,
    /// `dimensions == 0`
    DimensionsTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::DimensionsTooLarge => "dimensions above 3 are not supported",
            Error::DimensionsTooSmall => "dimensions below 1 are not supported",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl std::error::Error for Error {}

impl<R: rand::RngCore, RD: rand_distr::Distribution<f64>, T, const D: usize> Flight<R, RD, T, D> {
    //where R: rand::RngCore {
    pub fn new(rng: Box<R>, dist: Box<RD>, bounds: [T; D]) -> Result<Flight<R, RD, T, D>, Error> {
        let dimensions: usize = D;
        // TODO: Can this be managed by the traits implemented
        if dimensions > 3 {
            return Err(Error::DimensionsTooLarge);
        }
        if dimensions < 1 {
            return Err(Error::DimensionsTooSmall);
        }
        // TODO pass aloing Flight errors
        Ok(Flight {
            rng: rng,
            distribution: dist,
            bounds: bounds,
        })
    }
}

// Should the struct be typed instead?
pub trait Step<T, const D: usize> {
    // Assigns the new position in 'end'
    // TODO: should this return the direction/angle?
    fn step(&mut self, start: &[T; D], end: &mut [T; D]);
}

// For u64, we quantize. For f64, we don't.
impl<R: rand::RngCore, RD: rand_distr::Distribution<f64>> Step<u64, 1> for Flight<R, RD, u64, 1> {
    // How should the interface look for dimensions
    // Return array of points?
    fn step(&mut self, start: &[u64; 1], end: &mut [u64; 1]) {
        let val: f64 = self.distribution.sample(&mut self.rng);
        let q = val as u64; // TODO a little wonky here :)
                            // Pick the directionality using a uniform random.
        if self.rng.gen::<f64>() > 0.5 {
            // TODO add a saturate or modulo option
            if start[0] + q >= self.bounds[0] {
                end[0] = self.bounds[0] - 1;
            }
            end[0] = start[0] + q;
        } else {
            if q > start[0] {
                end[0] = 0;
            }
            end[0] = start[0] - q;
        }
    }
}

impl<R: rand::RngCore, RD: rand_distr::Distribution<f64>> Step<u64, 2> for Flight<R, RD, u64, 2> {
    // How should the interface look for dimensions
    // Return array of points?
    fn step(&mut self, start: &[u64; 2], end: &mut [u64; 2]) {
        let val: f64 = self.distribution.sample(&mut self.rng);
        let angle: f64 = (self.rng.gen::<f64>() * 360.0).to_radians();
        // println!("val: {} angle: {}rad", val, angle);
        // println!("{} {}", val * angle.cos(), val * angle.sin());
        let x: i64 = (val * angle.cos()) as i64;
        let y: i64 = (val * angle.sin()) as i64;
        // println!("step-x {} step-y {}", x, y);
        if x.is_negative() {
            if x.abs() as u64 > start[0] {
                end[0] = 0;
            } else {
                end[0] = start[0] - x.abs() as u64;
            }
        } else {
            end[0] = start[0].checked_add(x as u64).unwrap_or(self.bounds[0] - 1);
        }
        if y.is_negative() {
            if y.abs() as u64 > start[1] {
                end[1] = 0;
            } else {
                end[1] = start[1] - y.abs() as u64;
            }
        } else {
            end[1] = start[1].checked_add(y as u64).unwrap_or(self.bounds[1] - 1);
        }
        if end[0] >= self.bounds[0] {
            end[0] = self.bounds[0] - 1;
        }
        if end[1] >= self.bounds[1] {
            end[1] = self.bounds[1] - 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use levy_distr::Levy;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_distr::Pareto;

    #[test]
    fn levy_works_1d() {
        let min_step = 1.0;
        let alpha = 1.4;
        let rng = Box::new(SeedableRng::seed_from_u64(1));
        let dist = Box::new(Levy::<f64>::new(min_step, alpha).unwrap());
        let mut lf = Flight::<StdRng, Levy<f64>, u64, 1>::new(rng, dist, &[200]).unwrap();
        let mut result = [0];
        lf.step(&[10], &mut result);
        assert_eq!(result[0], 23);
    }

    #[test]
    fn levy_works_2d() {
        let min_step = 1.0;
        let alpha = 0.9;
        let rng = Box::new(SeedableRng::seed_from_u64(1));
        let dist = Box::new(Levy::<f64>::new(min_step, alpha).unwrap());
        let mut lf = Flight::<StdRng, Levy<f64>, u64, 2>::new(rng, dist, &[200, 200]).unwrap();

        // Show a sequence with at least one large jump and many small
        // moves to help validate the shift to 2d.
        let mut result = [0, 0];
        let mut start = [100, 100];
        lf.step(&start, &mut result);
        assert_eq!(result, [79, 46]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [79, 47]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [80, 47]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [80, 46]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [79, 47]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [80, 47]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [61, 55]);
    }

    #[test]
    fn pareto_works_2d() {
        let scale = 100.0;
        let shape = 2.0;
        let rng = Box::new(SeedableRng::seed_from_u64(1));
        let dist = Box::new(Pareto::new(scale, shape).unwrap());
        let mut lf = Flight::<StdRng, Pareto<f64>, u64, 2>::new(rng, dist, &[200, 200]).unwrap();

        // Show a sequence with at least one large jump and many small
        // moves to help validate the shift to 2d.
        let mut result = [0, 0];
        let mut start = [100, 100];
        lf.step(&start, &mut result);
        assert_eq!(result, [64, 6]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [132, 142]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [199, 96]);
        start = result;
        lf.step(&start, &mut result);
        assert_eq!(result, [158, 0]);
    }
}
