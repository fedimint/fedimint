// rand 0.6 -> rand 0.7 adapter
pub struct Rand07Compat<R: rand::RngCore>(pub R);

impl<R: rand::RngCore> rand07::RngCore for Rand07Compat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand07::Error> {
        self.0.try_fill_bytes(dest).map_err(rand07::Error::new)
    }
}

impl<R: rand::RngCore + rand::CryptoRng> rand07::CryptoRng for Rand07Compat<R> {}
