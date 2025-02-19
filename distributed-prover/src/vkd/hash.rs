use crate::poseidon_util::gen_poseidon_params;
use crate::vkd::util::*;
use crate::vkd::{InnerHash, INNER_HASH_SIZE};
use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::{
    CRHGadget, CRHParametersVar, TwoToOneCRHGadget,
};
use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::crh::{
    poseidon, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_crypto_primitives::Error as ErrorArkWorks;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::{R1CSVar, ToBitsGadget, ToBytesGadget};
use ark_relations::r1cs::SynthesisError;
use digest::Digest;
use lazy_static::lazy_static;
use std::cmp::PartialEq;

lazy_static! {
    // Capacity-2/3 Poseidon parameters
    static ref POSEIDON_PARAMS_CAP2: PoseidonConfig<Fr> =  gen_poseidon_params(2, false);
    static ref POSEIDON_PARAMS_CAP3: PoseidonConfig<Fr> =  gen_poseidon_params(3, false);
}

pub const HASH_TYPE: HashType = HashType::Poseidon;

// pub const SHA256_PARAMETERS: &() = &();

/*
 *
 * Non-ZK Hash Functions
 *
 */

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum HashType {
    Sha256,
    Poseidon,
}

pub fn hash_leaf(leaf: &[u8]) -> Result<InnerHash, ErrorArkWorks> {
    let digest = &hash(leaf).unwrap()[0..INNER_HASH_SIZE];
    Ok(InnerHash::try_from(digest).unwrap())
}

pub fn hash_inner_node(left: &InnerHash, right: &InnerHash) -> Result<InnerHash, ErrorArkWorks> {
    if HASH_TYPE == HashType::Sha256 {
        // concat left and right hashes
        let mut combined_hash: [u8; INNER_HASH_SIZE * 2] = [0; 2 * INNER_HASH_SIZE];
        combined_hash[..INNER_HASH_SIZE].copy_from_slice(left);
        combined_hash[INNER_HASH_SIZE..].copy_from_slice(right);
        // apply hash
        let sha256_digest = Sha256::digest(&combined_hash);
        let digest_bytes = sha256_digest.as_slice();
        // convert to inner hash
        Ok(InnerHash::try_from(&digest_bytes[0..INNER_HASH_SIZE]).unwrap())
    } else {
        let poseidon_params: &PoseidonConfig<Fr> = &*POSEIDON_PARAMS_CAP2;
        // convert the inner nodes to F
        let left_field_element = Fr::from_le_bytes_mod_order(left);
        let right_field_element = Fr::from_le_bytes_mod_order(right);
        // apply the hash function
        let poseidon_output: Fr = poseidon::TwoToOneCRH::evaluate(
            poseidon_params,
            left_field_element,
            right_field_element,
        )
        .unwrap();
        // convert to inner hash
        Ok(
            InnerHash::try_from(&poseidon_output.to_sponge_bytes_as_vec()[0..INNER_HASH_SIZE])
                .unwrap(),
        )
    }
}

pub fn hash(value: &[u8]) -> Result<Vec<u8>, ErrorArkWorks> {
    if HASH_TYPE == HashType::Sha256 {
        let sha256_digest = Sha256::digest(value);
        let digest_bytes = sha256_digest.as_slice();
        let digest_vec: Vec<u8> = digest_bytes.into();
        Ok(digest_vec)
    } else {
        let poseidon_params: &PoseidonConfig<Fr> = &*POSEIDON_PARAMS_CAP3;
        // convert the value into a vector of F
        let field_vector: Vec<Fr> = value
            .chunks(INNER_HASH_SIZE)
            .map(|chunk| Fr::from_le_bytes_mod_order(chunk))
            .collect::<Vec<Fr>>();
        // apply the hash function
        let mut sponge = PoseidonSponge::new(&poseidon_params);
        for field_element in field_vector {
            sponge.absorb(&field_element);
        }
        let squeezed_field_element: Vec<Fr> = sponge.squeeze_field_elements(1);
        let field_element_bytes = &squeezed_field_element[0].to_sponge_bytes_as_vec()[0..32];
        Ok(field_element_bytes.to_vec())
    }
}

/*
 *
 * ZK Hash Functions
 *
 */

pub fn hash_leaf_var(leaf: &Vec<UInt8<Fr>>) -> Result<FpVar<Fr>, SynthesisError> {
    let digest: [UInt8<Fr>; 32] = hash_var(leaf).unwrap();
    let digest_var = DigestVar(digest[0..INNER_HASH_SIZE].to_vec());
    digest_to_fpvar(digest_var)
}

// TODO: this is not standard, there's a non-necessary conversion from FpVar to Digest which can be resolved
// By changing the sparse tree type to Fp or for the sake of generality a new type that supports both Fp and [u8; 32]
// But it's a big refactor and for our benchmark purposes it suffices to do in the non-standard way
pub fn hash_inner_node_var(
    left_input: &FpVar<Fr>,
    right_input: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let digest_var_result: DigestVar<Fr>;
    if HASH_TYPE == HashType::Sha256 {
        // Convert the hashes back into bytes and concat them
        let left_input_bytes = fpvar_to_digest(left_input).unwrap();
        let right_input_bytes = fpvar_to_digest(right_input).unwrap();
        let contacted_bytes = [left_input_bytes, right_input_bytes]
            .concat()
            .into_iter()
            .collect::<Vec<_>>();
        // hash the result and return only the 31 first bytes
        digest_var_result = Sha256Gadget::digest(&contacted_bytes).unwrap();
        digest_to_fpvar(digest_var_result)
    } else {
        let cs = left_input.cs().or(right_input.cs());
        let poseidon_params_var =
            CRHParametersVar::<Fr>::new_witness(cs, || Ok(&*POSEIDON_PARAMS_CAP2)).unwrap();
        let poseidon_digest =
            TwoToOneCRHGadget::evaluate(&poseidon_params_var, left_input, right_input).unwrap();
        // TODO: NOT STANDARD
        let digest_value = poseidon_digest.value().unwrap_or(Fr::ZERO);
        let truncated_digest_value = Fr::from_le_bytes_mod_order(
            &digest_value.to_sponge_bytes_as_vec()[0..INNER_HASH_SIZE].to_vec(),
        );
        FpVar::new_witness(poseidon_digest.cs(), || Ok(truncated_digest_value))
    }
}

pub fn hash_var(leaf: &Vec<UInt8<Fr>>) -> Result<[UInt8<Fr>; 32], SynthesisError> {
    if HASH_TYPE == HashType::Sha256 {
        let sha256_digest_var = DigestVar(leaf.to_vec());
        let digest_result = Sha256Gadget::digest(&sha256_digest_var.0).unwrap();
        Ok(<[UInt8<Fr>; 32]>::try_from(digest_result.0).unwrap())
    } else {
        let cs = leaf[0].cs();
        let poseidon_params_var =
            CRHParametersVar::<Fr>::new_witness(cs, || Ok(&*POSEIDON_PARAMS_CAP3)).unwrap();
        // convert the value into a vector of F
        let leaf_as_field_vector: Vec<FpVar<Fr>> = leaf
            .chunks(INNER_HASH_SIZE)
            .map(|chunk| {
                let bits = chunk
                    .into_iter()
                    .flat_map(|byte| byte.to_bits_le().unwrap())
                    .collect::<Vec<Boolean<Fr>>>();
                Boolean::le_bits_to_fp_var(&bits).unwrap()
            })
            .collect::<Vec<FpVar<Fr>>>();
        // apply the hash function
        let digest_field_value =
            CRHGadget::evaluate(&poseidon_params_var, leaf_as_field_vector.as_slice()).unwrap();
        Ok(
            <[UInt8<Fr>; 32]>::try_from(digest_field_value.to_bytes().unwrap()[0..32].to_vec())
                .unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::vkd::hash::{hash, hash_leaf, hash_leaf_var, hash_var};
    use ark_bls12_381::Fr;
    use ark_crypto_primitives::sponge::Absorb;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_r1cs_std::uint8::UInt8;
    use ark_r1cs_std::{R1CSVar, ToBytesGadget};
    use std::str::FromStr;

    #[test]
    fn comparison() {
        let random_field_element = Fr::from_str(
            "12242166908188651009877250812424843524687801523336557272219921456462821518061",
        )
        .unwrap();
        let random_field_element_var = FpVar::constant(random_field_element);
        println!(
            "{:?}",
            random_field_element_var
                .to_bytes()
                .unwrap()
                .into_iter()
                .map(|byte| byte.value().unwrap())
                .collect::<Vec<u8>>()
        );
        println!("{:?}", random_field_element.to_sponge_bytes_as_vec());

        let leaf = [0u8; 32];
        let leaf_var = UInt8::constant_vec(&leaf);
        let leaf_hash = hash(&leaf).unwrap();
        let leaf_hash_var = hash_var(&leaf_var).unwrap();
        println!(
            "{:?}",
            leaf_hash_var
                .to_bytes()
                .unwrap()
                .into_iter()
                .map(|byte| byte.value().unwrap())
                .collect::<Vec<u8>>()
        );
        println!("{:?}", leaf_hash);

        let leaf_hash = hash_leaf(&leaf).unwrap();
        let leaf_hash_var = hash_leaf_var(&leaf_var).unwrap();
        println!(
            "{:?}",
            leaf_hash_var
                .to_bytes()
                .unwrap()
                .into_iter()
                .map(|byte| byte.value().unwrap())
                .collect::<Vec<u8>>()
        );
        println!("{:?}", leaf_hash);
    }
}
