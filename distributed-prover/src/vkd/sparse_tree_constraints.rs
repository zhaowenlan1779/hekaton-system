use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::*,
};

use crate::vkd::sparse_tree::{MerkleTreeParameters, MerkleTreePath};

use crate::vkd::hash::{hash_inner_node_var, hash_leaf_var};
use crate::vkd::util::*;
use ark_bls12_381::Fr;
use std::{borrow::Borrow, marker::PhantomData};

#[derive(Clone)]
pub struct MerkleTreePathVar<P>
where
    P: MerkleTreeParameters,
{
    path: Vec<FpVar<Fr>>,
    _parameters: PhantomData<P>,
}

impl<P> MerkleTreePathVar<P>
where
    P: MerkleTreeParameters,
{
    pub fn compute_root_var_from_leaf(
        &self,
        leaf: &Vec<UInt8<Fr>>,
        index: &Vec<Boolean<Fr>>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let mut current_hash = hash_leaf_var(leaf)?;
        for (i, b) in index.iter().take(self.path.len()).enumerate() {
            let lc = FpVar::conditionally_select(b, &self.path[i], &current_hash)?;
            let rc = FpVar::conditionally_select(b, &current_hash, &self.path[i])?;
            current_hash = hash_inner_node_var(&lc, &rc)?;
        }
        Ok(current_hash)
    }

    pub fn compute_root_var_from_internal_node(
        &self,
        internal_node: &FpVar<Fr>,
        index: &Vec<Boolean<Fr>>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let mut current_hash = internal_node.clone();
        for (i, b) in index.iter().take(self.path.len()).enumerate() {
            let lc = FpVar::conditionally_select(b, &self.path[i], &current_hash)?;
            let rc = FpVar::conditionally_select(b, &current_hash, &self.path[i])?;
            current_hash = hash_inner_node_var(&lc, &rc)?;
        }
        Ok(current_hash)
    }

    pub fn check_path_from_leaf(
        &self,
        root: &FpVar<Fr>,
        leaf: &Vec<UInt8<Fr>>,
        index: &Vec<Boolean<Fr>>,
    ) -> Result<(), SynthesisError> {
        self.conditional_check_path_from_leaf(root, leaf, index, &Boolean::constant(true))
    }

    pub fn check_path_from_internal_node(
        &self,
        root: &FpVar<Fr>,
        internal_node: &FpVar<Fr>,
        index: &Vec<Boolean<Fr>>,
    ) -> Result<(), SynthesisError> {
        self.conditional_check_path_from_internal_node(
            root,
            internal_node,
            index,
            &Boolean::constant(true),
        )
    }

    pub fn conditional_check_path_from_leaf(
        &self,
        root: &FpVar<Fr>,
        leaf: &Vec<UInt8<Fr>>,
        index: &Vec<Boolean<Fr>>,
        condition: &Boolean<Fr>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root_var_from_leaf(leaf, index)?;
        root.conditional_enforce_equal(&computed_root, condition)
    }

    pub fn conditional_check_path_from_internal_node(
        &self,
        root: &FpVar<Fr>,
        internal_node: &FpVar<Fr>,
        index: &Vec<Boolean<Fr>>,
        condition: &Boolean<Fr>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root_var_from_internal_node(internal_node, index)?;
        root.conditional_enforce_equal(&computed_root, condition)
    }
}

impl<P> AllocVar<MerkleTreePath<P>, Fr> for MerkleTreePathVar<P>
where
    P: MerkleTreeParameters,
{
    fn new_variable<T: Borrow<MerkleTreePath<P>>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let mut vec = Vec::new();
        for value in f()?.borrow().path.iter() {
            let fp = inner_hash_to_fpvar(cs.clone(), value, mode);
            vec.push(fp?);
        }
        Ok(MerkleTreePathVar {
            path: vec,
            _parameters: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vkd::hash::hash;
    use crate::vkd::sparse_tree::*;
    use crate::vkd::vkd::DEPTH;
    use ark_r1cs_std::uint64::UInt64;
    use ark_relations::ns;
    use ark_relations::r1cs::ConstraintSystem;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: usize = DEPTH;
    }

    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;

    #[test]
    fn valid_path_constraints_test() {
        let mut tree = TestMerkleTree::new().unwrap();
        let leaf = [1_u8; 32];
        let leaf_hash = hash(&leaf).unwrap();
        let index = SparseMerkleTree::<MerkleTreeTestParameters>::get_index(
            leaf_hash.as_slice(),
            MerkleTreeTestParameters::DEPTH,
        )
        .unwrap();

        tree.insert(index.clone(), &leaf, NodeType::Leaf).unwrap();

        let path = tree.lookup_path(&index).unwrap();
        let path_first_half = MerkleTreePath {
            path: path.path[0..path.path.len() / 2].to_owned(),
            _parameters1: PhantomData,
            _parameters2: PhantomData,
        };
        let path_second_half = MerkleTreePath {
            path: path.path[path.path.len() / 2..].to_owned(),
            _parameters1: PhantomData,
            _parameters2: PhantomData,
        };

        let index_bool_vec = index.to_bit_vector();
        let (index_bool_vec_first_half, index_bool_vec_second_half) =
            index_bool_vec.split_at(path.path.len() / 2);
        let middle_root = path_first_half
            .compute_root(&leaf, &index_bool_vec_first_half.to_vec(), NodeType::Leaf)
            .unwrap();

        assert!(path_second_half
            .verify(
                &tree.root,
                &middle_root,
                &index_bool_vec_second_half.to_vec(),
                NodeType::InternalNode,
            )
            .unwrap());

        let cs = ConstraintSystem::<Fr>::new_ref();

        // Allocate root
        let root_var = inner_hash_to_fpvar(cs.clone(), &tree.root, AllocationMode::Input).unwrap();

        // Allocate root
        let middle_root_var =
            inner_hash_to_fpvar(cs.clone(), &middle_root, AllocationMode::Input).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fr>>::new_witness(ns!(cs, "leaf"), || Ok(leaf)).unwrap();

        // Allocate leaf
        let middle_root_fpvar =
            inner_hash_to_fpvar(cs.clone(), &middle_root, AllocationMode::Input).unwrap();

        // Allocate index  m
        let mut fixed_size_array: [u8; 8] = [0; 8];
        fixed_size_array.copy_from_slice(&leaf_hash.as_slice()[0..8]);
        let hash_as_u64 = u64::from_le_bytes(fixed_size_array);
        let index_var_u64 =
            UInt64::<Fr>::new_witness(ns!(cs, "index"), || Ok(hash_as_u64)).unwrap();
        let index_var_boolean_vec = index_var_u64.to_bits_le();
        let (index_var_first_half, index_var_second_half) =
            index_var_boolean_vec.split_at(path.path.len() / 2);

        // Allocate path first half
        let path_var_first_half =
            MerkleTreePathVar::<MerkleTreeTestParameters>::new_witness(ns!(cs, "path"), || {
                Ok(path_first_half)
            })
            .unwrap();

        // Allocate path second half
        let path_var_second_half =
            MerkleTreePathVar::<MerkleTreeTestParameters>::new_witness(ns!(cs, "path"), || {
                Ok(path_second_half)
            })
            .unwrap();

        // hash the leaf to reach an internal node
        path_var_first_half
            .check_path_from_leaf(&middle_root_var, &leaf_var, &index_var_first_half.to_vec())
            .unwrap();
        assert!(cs.is_satisfied().unwrap());

        path_var_second_half
            .check_path_from_internal_node(
                &root_var,
                &middle_root_fpvar,
                &index_var_second_half.to_vec(),
            )
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
