// Copyright 2022 Google
// Based on rand_distr's Pareto distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The Levy distribution.

use core::fmt;
use rand::Rng;
use rand_distr::num_traits::Float;
use rand_distr::{Distribution, OpenClosed01};

/// Samples floating-point numbers according to the Levy distribution
///
/// It is implemented using inverse transform sampling to approximate
/// the continuous discrete function (CDF):
///
///   CDF(t) = {
///              0 for t < t_0,
///              1 - (t/t_0)^-alpha for t >= t0
///            }
///
/// where t is the step size and t_0 is the minimum step size
/// and alpha is the slope of the power law. To apply inverse transform
/// sampling, we compute the inverse of the CDF, CDF^-1(u):
///   u = 1 - (y/t_0)^-alpha
///   1 - u =  (y/t_0)^-alpha
///   1 - u = y^-alpha * (1/t_0)^-alpha
///   (1 - u)^(1/-alpha) = y/t_0
///   t_0(1-u)^(1/-alpha) = y
///   y = t_0 (1 - u)^(1 / -alpha)
///   F^-1(u) = t_0 (1 - u)^(1 / -alpha)
///   where F^-1(u) generates a random variable which is
///   always larger than the minimum step.
///
/// u is the uniform random variable which is sampled.
///
/// # Example
/// ```
/// use rand::prelude::*;
/// use levy_distr::Levy;
///
/// let val: f64 = thread_rng().sample(Levy::new(0.1, 1.5).unwrap());
/// println!("{}", val);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct Levy<F>
where
    F: Float,
    OpenClosed01: Distribution<F>,
{
    minimum_step: F,
    power_law_slope: F,
}

/// Error type returned from `Levy::new`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `minimum_step <= 0` or `nan`.
    MinimumStepTooSmall,
    /// `power_law_slope <= 0` or `nan`.
    PowerLawSlopeTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::MinimumStepTooSmall => "minimum step is not positive in Levy distribution",
            Error::PowerLawSlopeTooSmall => "power law slope is not positive in Levy distribution",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl std::error::Error for Error {}

impl<F> Levy<F>
where
    F: Float,
    OpenClosed01: Distribution<F>,
{
    /// Construct a new Levy distribution with given `minimum_step` and `power_law_slope`.
    ///
    /// In the literature, `minimum_step` is commonly written as t<sub>0</sub> and
    /// `power_law_slope` is often written as 𝛼
    pub fn new(minimum_step: F, power_law_slope: F) -> Result<Levy<F>, Error> {
        let zero = F::zero();

        if !(minimum_step > zero) {
            return Err(Error::MinimumStepTooSmall);
        }
        if !(power_law_slope > zero) {
            return Err(Error::PowerLawSlopeTooSmall);
        }
        Ok(Levy {
            minimum_step,
            power_law_slope,
        })
    }
}

impl<F> Distribution<F> for Levy<F>
where
    F: Float,
    OpenClosed01: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F {
        let u: F = OpenClosed01.sample(rng);
        let y: F = self.minimum_step
            * (F::from(1.0).unwrap() - u).powf(F::from(1.0).unwrap() / -self.power_law_slope);
        return y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::{Debug, Display, LowerExp};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    #[should_panic]
    fn invalid_0s() {
        Levy::new(0., 0.).unwrap();
    }

    #[test]
    fn sample() {
        let min_step = 1.0;
        let alpha = 1.4;
        let d = Levy::new(min_step, alpha).unwrap();
        let mut rng: StdRng = SeedableRng::seed_from_u64(1);
        for _ in 0..1000 {
            let r = d.sample(&mut rng);
            assert!(r >= min_step);
        }
    }

    #[test]
    fn value_stability() {
        fn test_samples<F: Float + Debug + Display + LowerExp, D: Distribution<F>>(
            distr: D,
            expected: &[F],
        ) {
            let mut rng: StdRng = SeedableRng::seed_from_u64(1);
            for v in expected {
                let x = rng.sample(&distr);
                assert_eq!(x, *v);
            }
        }

        test_samples(
            Levy::new(0.1, 1.5).unwrap(),
            &[
                1.1466283540189062,
                0.21890139502526984,
                0.14511864553139828,
                0.1137373517929057,
            ],
        );
        test_samples(
            Levy::new(2.0, 0.5).unwrap(),
            &[
                3015.0743516589905,
                20.978555614868867,
                6.112229383909227,
                2.9426548922777163,
            ],
        );
    }

    #[test]
    fn levyflight_distributions_can_be_compared() {
        assert_eq!(Levy::new(1.0, 2.0), Levy::new(1.0, 2.0));
    }
}
