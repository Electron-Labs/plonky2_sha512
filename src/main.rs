use std::time::Instant;

use plonky2::{hash::hash_types::RichField, field::extension::Extendable, plonk::{config::{GenericConfig, PoseidonGoldilocksConfig}, circuit_data::CircuitConfig, circuit_builder::CircuitBuilder}, iop::witness::{PartialWitness, WitnessWrite}};
use anyhow::Result;
use plonky2_sha512::gadgets::sha512::{array_to_bits, make_sha512_circuit};
use sha2::{Sha512, Digest};

fn prove_sha512<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8]
) -> Result<()> {
    let mut hasher = Sha512::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let len = msg.len()*8;
    let msg_bits = array_to_bits(msg);
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = make_sha512_circuit(&mut builder, len as u128);
    let mut pw = PartialWitness::new();
    for i in 0..len {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }
    let expected_res = array_to_bits(hash.as_slice());
    for i in 0..expected_res.len() {
        if expected_res[i] {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }
    println!("Circuit has {} gates", builder.num_gates());
    let circuit_build_time = Instant::now();
    let data = builder.build::<C>();
    println!("Time taken to build the circuit the proof - {:?}", circuit_build_time.elapsed());
    let proof_gen_time = Instant::now();
    let proof = data.prove(pw).unwrap();
    println!("Time taken to generate the proof - {:?}", proof_gen_time.elapsed());
    let proof_verfcn_time = Instant::now();
    println!("Time taken to verify the proof - {:?}", proof_verfcn_time.elapsed());
    data.verify(proof)
}

fn benchmark_sha512() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const MSG_SIZE: usize = 128;
    let mut msg = vec![0; MSG_SIZE as usize];
    for i in 0..MSG_SIZE - 1 {
        msg[i] = i as u8;
    }
    prove_sha512::<F,C,D>(&msg)
}

fn main() {
    let _ = benchmark_sha512();
}
