use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder, iop::target::BoolTarget};
use plonky2_crypto::u32::arithmetic_u32::{U32Target, CircuitBuilderU32};
use plonky2::field::extension::Extendable;
use plonky2_crypto::u32::interleaved_u32::CircuitBuilderB32;

// Constants necessary for SHA-256 family of digests.
// These values are the first 64 bits of the fractional parts of the cube roots of the first 80 prime numbers
#[rustfmt::skip]
pub const ROUND_CONSTANTS_: [u64; 80] = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
                            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

// Initial state for SHA-512.
// These values are the first 64 bits of the fractional parts of the square roots of the first eight prime numbers
#[rustfmt::skip]
pub const INITIAL_HASH_: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
                        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

                        
#[derive(Clone, Debug)]
pub struct U64Target {
    pub limbs: [U32Target; 2],
}

pub struct Sha512Targets {
    pub message: Vec<BoolTarget>,
    pub digest: Vec<BoolTarget>,
}

pub fn array_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for &byte in bytes.iter() {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

pub fn convert_bits_to_u64_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: &Vec<BoolTarget>
) -> Vec<U64Target> {
    let mut msg_u64: Vec<U64Target> = Vec::<U64Target>::new();
    for i in (0..msg.len()).step_by(64){
        let u32_limb_0 = U32Target(builder.le_sum(msg[i..i+32].iter().rev()));
        let u32_limb_1 = U32Target(builder.le_sum(msg[i+32..i+64].iter().rev()));
        let target = U64Target{ limbs: [u32_limb_1, u32_limb_0]};
        msg_u64.push(target);
    }
    msg_u64
}

pub fn convert_u64_to_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: u64
) -> U64Target {
    let output_low = (x & 0xFFFFFFFF) as u32;
    let output_high = (x >> 32) as u32;
    let u32_limb_0 = builder.constant_u32(output_high);
    let u32_limb_1 = builder.constant_u32(output_low);
    U64Target{ limbs: [u32_limb_1, u32_limb_0]}
}

pub fn rshift_u64target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: U64Target,
    n: u8
) -> U64Target {
    let shifted_low = builder.rsh_u32(x.limbs[0], n);
    let shifted_high = builder.rsh_u32(x.limbs[1], n);
    let cross = builder.lsh_u32(x.limbs[1], 32-n);
    let not_shifted_low = builder.not_u32(shifted_low);
    let not_cross = builder.not_u32(cross);
    let and_nots = builder.and_u32(not_shifted_low, not_cross);
    let new_low = builder.not_u32(and_nots);
    U64Target { limbs: [new_low, shifted_high] }
}

pub fn add_u64targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[U64Target]
) -> U64Target{
    let mut values_low: Vec<U32Target> = Vec::new();
    let mut values_high: Vec<U32Target> = Vec::new();
    for i in 0..values.len(){
        values_low.push(values[i].limbs[0]);
        values_high.push(values[i].limbs[1]);
    }
    let (low_addition_lo, low_addition_hi) = builder.add_many_u32(&values_low);
    let (high_addition_lo, _high_addition_hi) = builder.add_many_u32(&values_high);
    let (high_addition_lo_carry_lo, _high_addition_lo_carry_hi) = builder.add_u32(high_addition_lo, low_addition_hi);
    return U64Target{limbs: [low_addition_lo, high_addition_lo_carry_lo]}
}

//https://medium.com/@zaid960928/cryptography-explaining-sha-512-ad896365a0c1
pub fn make_sha512_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len: u128, // number of bits
) -> Sha512Targets {
    // 1. Preprocessing Input
    /*
        msg + padding_bits + len(msg) = N*1024
        padding_bits = '0' bits with a leading '1' -> '100..'
        | ----- msg ----- | | ----- padding_bits ----- | | ----- len(msg) ----- |
        |   L<=2**128-2   | |         P>=1             | |         128          |
        | <----------- ( N*1024 - 128 ) bits --------->|
     */
    let mut preprocessed_input_len = 0;

    let mut input: Vec<BoolTarget> = Vec::new();
    for _i in 0..msg_len{
        input.push(builder.add_virtual_bool_target_unsafe());
        preprocessed_input_len += 1;
    }
    // add necessary padding for p>=1
    input.push(builder.constant_bool(true));
    preprocessed_input_len += 1;
    // append padding till only 128 bits for msg len are left in 1024 len block
    while preprocessed_input_len%1024 != 896 {
        input.push(builder.constant_bool(false));
        preprocessed_input_len+=1
    }
    // append input len as 128 bits (msb to lsb)
    for i in 0..128 {
        let len_bit = ((msg_len as u128) >> (127 - i)) & 1;
        input.push(builder.constant_bool(len_bit == 1));
    }

    let input_u64 = convert_bits_to_u64_target(builder, &input);

    let mut round_constants_u64_target: Vec<U64Target> = Vec::<U64Target>::new();
    for const_ in ROUND_CONSTANTS_{
        round_constants_u64_target.push(convert_u64_to_target(builder, const_));
    }

    let mut sha_hashes: Vec<U64Target> = Vec::<U64Target>::new();
    for hash in INITIAL_HASH_{
        sha_hashes.push(convert_u64_to_target(builder, hash));
    }

    // 2. Message Processing (Process the input in consecutive 1024 bit chunks)
    for i in (0..input_u64.len()).step_by(16){

        let mut w: Vec<U64Target> = Vec::new();

        for j in 0..16 {
            w.push(input_u64[i+j].clone());
        }

        for _j in 16..80{
            w.push(convert_u64_to_target(builder, 0));
        }

        for j in 16..80{
            let s0_0 = builder.rrot_u64(&w[j-15].limbs, 1);
            let s0_1 = builder.rrot_u64(&w[j-15].limbs, 8);
            let s0_2 = rshift_u64target(builder, w[j-15].clone(), 7);
            let s0 = U64Target{ 
                    limbs: builder.unsafe_xor_many_u64(&[
                    s0_0, s0_1, s0_2.limbs
                ])};

            let s1_0 = builder.rrot_u64(&w[j-2].limbs, 19);
            let s1_1 = builder.rrot_u64(&w[j-2].limbs, 61);
            let s1_2 = rshift_u64target(builder, w[j-2].clone(), 6);
            let s1 = U64Target {
                    limbs: builder.unsafe_xor_many_u64(&[
                    s1_0, s1_1, s1_2.limbs
                ])};
            let sum = add_u64targets(builder,
                &[w[j-16].clone(), s0, w[j-7].clone(), s1]
            );
            w[j] = sum;
        }

        let mut a = sha_hashes[0].clone();
        let mut b = sha_hashes[1].clone();
        let mut c = sha_hashes[2].clone();
        let mut d = sha_hashes[3].clone();
        let mut e = sha_hashes[4].clone();
        let mut f = sha_hashes[5].clone();
        let mut g = sha_hashes[6].clone();
        let mut h = sha_hashes[7].clone();

        for j in 0..80{
            let sum1_0 = builder.rrot_u64(&e.limbs, 14);
            let sum1_1 = builder.rrot_u64(&e.limbs, 18);
            let sum1_2 = builder.rrot_u64(&e.limbs, 41);
            let sum1 = U64Target{limbs: builder.unsafe_xor_many_u64(
                &[sum1_0, sum1_1, sum1_2]
            )};

            let ch_0 = builder.and_u64(&e.limbs, &f.limbs);
            let ch_1_0 = builder.not_u64(&e.limbs);
            let ch_1 = builder.and_u64(&ch_1_0, &g.limbs);
            let ch = U64Target{limbs:builder.unsafe_xor_many_u64(&[ch_0, ch_1])};

            let temp1 = add_u64targets(builder, 
                &[h, sum1, ch, round_constants_u64_target[j].clone(), w[j].clone()]
            );
            
            let sum0_0 = builder.rrot_u64(&a.limbs, 28);
            let sum0_1 = builder.rrot_u64(&a.limbs, 34);
            let sum0_2 = builder.rrot_u64(&a.limbs, 39);
            let sum0 = U64Target{
                limbs: builder.unsafe_xor_many_u64(
                    &[sum0_0, sum0_1, sum0_2]
            )};
            
            let maj_0 = builder.and_u64(&a.limbs, &b.limbs);
            let maj_1 = builder.and_u64(&a.limbs, &c.limbs);
            let maj_2 = builder.and_u64(&b.limbs, &c.limbs);
            let maj = U64Target{
                limbs : builder.unsafe_xor_many_u64(&[maj_0, maj_1, maj_2])
            };

            let temp2 = add_u64targets(builder, &[sum0, maj]);

            h = g;
            g = f;
            f = e;
            e = add_u64targets(builder, &[d, temp1.clone()]);
            d = c;
            c = b;
            b = a;
            a = add_u64targets(builder, &[temp1, temp2]);
        }
        sha_hashes[0] = add_u64targets(builder, &[sha_hashes[0].clone(),a]);
        sha_hashes[1] = add_u64targets(builder, &[sha_hashes[1].clone(),b]);
        sha_hashes[2] = add_u64targets(builder, &[sha_hashes[2].clone(),c]);
        sha_hashes[3] = add_u64targets(builder, &[sha_hashes[3].clone(),d]);
        sha_hashes[4] = add_u64targets(builder, &[sha_hashes[4].clone(),e]);
        sha_hashes[5] = add_u64targets(builder, &[sha_hashes[5].clone(),f]);
        sha_hashes[6] = add_u64targets(builder, &[sha_hashes[6].clone(),g]);
        sha_hashes[7] = add_u64targets(builder, &[sha_hashes[7].clone(),h]);
    }

    // 3. Output
    let mut digest: Vec<BoolTarget> = Vec::new();
    for i in 0..8 {
        for j in (0..2).rev(){
            let bit_targets = builder.split_le_base::<2>(sha_hashes[i].limbs[j].0, 32);
            for k in (0..32).rev(){
                digest.push(BoolTarget::new_unsafe(bit_targets[k]));
            }
        }
    }
    Sha512Targets{ message: input, digest }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use sha2::{Sha512, Digest};
    use rand::Rng;
    use anyhow::Result;
    use plonky2::{plonk::{config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_data::CircuitConfig}, iop::witness::{PartialWitness, WitnessWrite}};
    use super::*;
    
    #[test]
    pub fn test_sha512_circuit() -> Result<()>{
        let mut msg = Vec::new();
        for _i in 0..127{
            let x: u8 = rand::thread_rng().gen(); 
            msg.push(x);
        }
        let mut hasher = Sha512::new();
        hasher.update(msg.clone());
        let hash = hasher.finalize();

        let msg_bits = array_to_bits(&msg);
        let len = msg.len() * 8;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
        let targets = make_sha512_circuit(&mut builder, len as u128);
        let mut pw = PartialWitness::new();
        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i]);
        }

        let expected_hash = array_to_bits(hash.as_slice());
        for i in 0..expected_hash.len() {
            if expected_hash[i] {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }
        println!("Starting to build proof for {:?}", builder.num_gates());
        let data = builder.build::<C>();
        println!("Starting to generate the proof");
        let s = Instant::now();
        let proof = data.prove(pw).unwrap();
        println!("Proof generated in {:?}", s.elapsed());
        data.verify(proof)
    }
}