use crate::FromRandom;
use ff::Field;
use rand::RngCore;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul, MulAssign};

#[derive(Debug)]
pub struct Poly<G, S>
where
    G: Debug,
{
    coefficients: Vec<G>,
    _pd: PhantomData<S>,
}

impl<G, S> Poly<G, S>
where
    G: Debug + MulAssign<S> + AddAssign<G> + FromRandom + Copy,
    S: Copy,
{
    pub fn random(degree: usize, rng: &mut impl RngCore) -> Self {
        assert_ne!(degree, usize::max_value());
        let coefficients = (0..=degree).map(|_| G::from_random(rng)).collect();
        Poly {
            coefficients,
            _pd: PhantomData,
        }
    }

    pub fn evaluate(&self, x: impl Into<S>) -> G {
        let mut result = *self
            .coefficients
            .last()
            .expect("Polynomial has no coefficients");
        let x: S = x.into();
        for &c in self.coefficients.iter().rev().skip(1) {
            result.mul_assign(x);
            result.add_assign(c);
        }
        result
    }
}

/// Interpolates the constant factor of a polynomial defined by the points supplied in `elements`.
///
/// # Panics
/// If less than 2 points are supplied.
pub fn interpolate_zero<G, S>(elements: impl Iterator<Item = (S, G)> + Clone) -> G
where
    G: Copy + Mul<S, Output = G> + Add<G, Output = G>,
    S: Copy + Field,
{
    let elements_closure = elements.clone();
    let lagrange_coefficient = move |i: usize| -> S {
        let xi = elements_closure.clone().skip(i).next().unwrap().0;

        elements_closure
            .clone()
            .enumerate()
            .filter_map(|(idx, (x, _))| {
                if idx != i {
                    Some(-x * (xi - x).invert().unwrap())
                } else {
                    None
                }
            })
            .reduce(|a, b| a * b)
            .expect("Elements may not be empty!")
    };

    elements
        .enumerate()
        .map(|(idx, (_, y))| y * lagrange_coefficient(idx))
        .reduce(|a, b| a + b)
        .expect("Elements may not be empty!")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_interpolate_simple() {
        use bls12_381::Scalar;

        // f(x) = 6 + 3x + 5x^2
        let vals = vec![
            (Scalar::from(1), Scalar::from(14)),
            (Scalar::from(2), Scalar::from(32)),
            (Scalar::from(3), Scalar::from(60)),
        ];
        assert_eq!(
            crate::poly::interpolate_zero(vals.into_iter()),
            Scalar::from(6)
        );
    }
}
