use simplicity::core::term_dag::TermDag;
use simplicity::extension::jets::JetsNode;
use simplicity::merkle::cmr::Cmr;
use simplicity::policy::compiler;
use simplicity::{Program, UntypedProgram, Value};
use std::rc::Rc;

/// Return a Simplicity hash contract that commits to the given hash image.
pub fn get_hash_commitment(image: &[u8]) -> UntypedProgram<(), JetsNode> {
    let image_value = Value::u256_from_slice(image);
    let dag = TermDag::comp(
        TermDag::pair(
            TermDag::comp(TermDag::witness(), TermDag::jet(JetsNode::Sha256)),
            Rc::new(compiler::scribe(image_value)),
        ),
        TermDag::jet(JetsNode::EqV256),
    );
    dag.to_untyped_program()
}

/// Return the CMR of the given Simplicity hash contract.
pub fn get_hash_cmr(program: UntypedProgram<(), JetsNode>) -> Cmr {
    let witness = vec![Value::u256_from_slice(&[0u8; 32])];
    let finalized = Program::from_witness_hack(program, witness).expect("finalizing");
    finalized.root_node().cmr
}

/// Return a Simplicity hash contract with the given hash preimage as witness.
pub fn get_hash_redemption(
    program: UntypedProgram<(), JetsNode>,
    preimage: &[u8],
) -> Program<JetsNode> {
    let witness = vec![Value::u256_from_slice(preimage)];
    Program::from_witness_hack(program, witness).expect("finalizing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::{sha256, Hash};
    use simplicity::exec::BitMachine;

    #[test]
    fn hash_contract() {
        let preimage = [0u8; 32];
        let image = sha256::Hash::hash(&preimage);

        // 1) Commitment time: Creation of a TX output (UTXO)
        let commitment = get_hash_commitment(&image);
        let cmr = get_hash_cmr(commitment.clone());

        // 2) Redemption time: Creation of a TX input
        // 2.1) Correct preimage
        let correct_redemption = get_hash_redemption(commitment.clone(), &preimage);
        assert_eq!(cmr, correct_redemption.root_node().cmr);

        let mut machine = BitMachine::for_program(&correct_redemption);
        assert!(machine.exec(&correct_redemption, &()).is_ok());

        // 2.2) False preimage
        let false_redemption = get_hash_redemption(commitment, &[1u8; 32]);
        assert_eq!(cmr, false_redemption.root_node().cmr);

        let mut machine = BitMachine::for_program(&false_redemption);
        assert!(machine.exec(&false_redemption, &()).is_err());
    }
}
