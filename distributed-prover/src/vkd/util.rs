use crate::vkd::{
    InnerHash, MerkleTreeError, MerkleTreeParameters, SparseMerkleTree, DEPTH, INNER_HASH_SIZE,
    PATH_LENGTH,
};
use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Truncates the SHA256 hash to 31 bytes, converts to bits (each byte to little-endian), and
/// interprets the resulting bit-string as a little-endian-encoded field element
pub fn digest_to_fpvar<F: PrimeField>(digest: DigestVar<F>) -> Result<FpVar<F>, SynthesisError> {
    let bits = digest
        .0
        .into_iter()
        .take(INNER_HASH_SIZE)
        .flat_map(|byte| byte.to_bits_le().unwrap())
        .collect::<Vec<_>>();
    Boolean::le_bits_to_fp_var(&bits)
}

/// Converts a field element back into the truncated digest that created it
pub fn fpvar_to_digest<F: PrimeField>(f: &FpVar<F>) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let bytes = f
        .to_bits_le()?
        .chunks(8)
        .take(INNER_HASH_SIZE)
        .map(UInt8::from_bits_le)
        .collect::<Vec<_>>();
    Ok(bytes)
}

pub fn split<T: Clone>(vector: Vec<T>, mut split_factor: usize) -> Result<Vec<Vec<T>>, Error> {
    if ![2, 4, 8, 16].contains(&split_factor) {
        return Err(Box::new(MerkleTreeError::InvalidParameter));
    }
    let mut length = vector.len();
    let mut res = Vec::new();
    res.push(vector.clone());
    while split_factor != 1 {
        length /= 2;
        split_factor /= 2;
        let mut temp = Vec::new();
        for vec in res.iter() {
            let (v1, v2) = vec.split_at(length);
            temp.push(v1.to_vec());
            temp.push(v2.to_vec());
        }
        res = temp;
    }
    Ok(res)
}

pub fn inner_hash_to_fpvar<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    digest: &InnerHash,
    mode: AllocationMode,
) -> Result<FpVar<F>, SynthesisError> {
    let fp = F::from_le_bytes_mod_order(digest);
    FpVar::new_variable(cs.clone(), || Ok(fp), mode)
}

// TODO: when chunks are less than size 8 it doesn't work
pub fn fpvar_to_boolean_index<F: PrimeField + Absorb>(
    fpvar: FpVar<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let boolean_vec = fpvar.to_bits_le().unwrap();
    let truncated_vec = &boolean_vec[0..PATH_LENGTH];
    Ok(truncated_vec.to_vec())
}

// this function returns split index both in Vec<bool> and Vec<Bool>
// [Bytes] ==> Fpvar ==> [Boolean] ==> this can be done for each part or a single part separately
pub fn hash_leaf_to_split_index<P: MerkleTreeParameters>(
    leaf_hash: &[u8],
    cs: ConstraintSystemRef<Fr>,
    mode: AllocationMode,
    split_factor: usize,
) -> (Vec<FpVar<Fr>>, Vec<Vec<bool>>) {
    let index = SparseMerkleTree::<P>::get_index(leaf_hash, P::DEPTH)
        .unwrap()
        .to_bit_vector();
    let split_index = split(index, split_factor).unwrap();

    let mut fixed_size_array: [u8; DEPTH / 8] = [0u8; DEPTH / 8];
    fixed_size_array.copy_from_slice(&leaf_hash[0..DEPTH / 8]);
    let split_leah_hash = split(fixed_size_array.to_vec(), split_factor).unwrap();

    let mut split_leaf_hash_fpvar_vec = Vec::new();
    for i in 0..split_factor {
        let mut fixed_size_array: [u8; PATH_LENGTH / 8] = [0u8; PATH_LENGTH / 8];
        fixed_size_array.copy_from_slice(&split_leah_hash[i].as_slice()[0..PATH_LENGTH / 8]);
        let fp = Fr::from_le_bytes_mod_order(&fixed_size_array);
        let fpvar = FpVar::new_variable(cs.clone(), || Ok(fp), mode).unwrap();
        split_leaf_hash_fpvar_vec.push(fpvar);
    }

    (split_leaf_hash_fpvar_vec, split_index)
}
