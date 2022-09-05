// rand 0.6 -> rand 0.8.5 adapter
pub struct Rand085Compat<R: rand::RngCore>(pub R);

impl<R: rand::RngCore> rand08::RngCore for Rand085Compat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand08::Error> {
        self.0.try_fill_bytes(dest).map_err(rand08::Error::new)
    }
}

impl<R: rand::RngCore + rand::CryptoRng> rand08::CryptoRng for Rand085Compat<R> {}
