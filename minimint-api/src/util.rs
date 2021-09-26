use crate::Amount;
use std::marker::PhantomData;

pub struct TieredMultiZip<'a, I, C>
where
    I: 'a,
{
    iters: Vec<I>,
    _pd: PhantomData<&'a C>,
}

impl<'a, I, C> TieredMultiZip<'a, I, C> {
    /// Creates a new MultiZip Iterator from `Coins` iterators. These have to be checked for
    /// structural equality! There also has to be at least one iterator in the `iter` vector.
    pub fn new(iters: Vec<I>) -> Self {
        assert!(iters.len() >= 1);

        TieredMultiZip {
            iters,
            _pd: Default::default(),
        }
    }
}

impl<'a, I, C> Iterator for TieredMultiZip<'a, I, C>
where
    I: Iterator<Item = (Amount, C)>,
{
    type Item = (Amount, Vec<C>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut coins = Vec::with_capacity(self.iters.len());
        let mut amount = None;
        for iter in self.iters.iter_mut() {
            match iter.next() {
                Some((amt, coin)) => {
                    if let Some(amount) = amount {
                        // This may fail if coins weren't tested for structural equality
                        assert_eq!(amount, amt);
                    } else {
                        amount = Some(amt);
                    }
                    coins.push(coin);
                }
                None => return None,
            }
        }

        // This should always hold as long as this impl is correct
        assert_eq!(coins.len(), self.iters.len());

        Some((
            amount.expect("The multi zip must contain at least one iterator"),
            coins,
        ))
    }
}
