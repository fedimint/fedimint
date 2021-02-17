use mint_api::PartialSigResponse;
use tbs::{BlindedMessage, BlindedSignatureShare};

pub struct PartialSigZip<'a> {
    psigs: &'a [&'a (usize, PartialSigResponse)],
    idx: usize,
    len: usize,
}

pub struct PartialSigZipIter<'a> {
    psigs: &'a [&'a (usize, PartialSigResponse)],
    row: usize,
    col: usize,
}

impl<'a> PartialSigZip<'a> {
    pub fn new(psigs: &'a [&'a (usize, PartialSigResponse)], len: usize) -> Self {
        PartialSigZip { psigs, idx: 0, len }
    }
}

impl<'a> Iterator for PartialSigZip<'a> {
    type Item = PartialSigZipIter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < self.len {
            let res_iter = PartialSigZipIter {
                psigs: self.psigs,
                row: self.idx,
                col: 0,
            };
            self.idx += 1;
            Some(res_iter)
        } else {
            None
        }
    }
}

impl<'a> Iterator for PartialSigZipIter<'a>
where
    Self: 'a,
{
    type Item = (&'a usize, &'a BlindedMessage, &'a BlindedSignatureShare);

    fn next(&mut self) -> Option<Self::Item> {
        if self.col < self.psigs.len() {
            let (peer_id, row) = &self.psigs[self.col];
            let (msg, sig) = &row.0[self.row];
            self.col += 1;
            Some((peer_id, msg, sig))
        } else {
            None
        }
    }
}
