use crate::portal_manager::PortalManager;
use crate::vkd::hash::hash;
use crate::vkd::{MerkleTreeParameters, MerkleTreePathVar, NodeType, SparseMerkleTree};
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::uint64::UInt64;
use ark_relations::r1cs::ConstraintSystemRef;
use std::marker::PhantomData;

pub const MERKLE_MEMORY_DEPTH: usize = 32;

pub struct Memory<'a, P: PortalManager<Fr>> {
    pub use_merkle_memory: bool,
    pub portal_manager: &'a mut P,
    pub phantom: PhantomData<Fr>,
}

#[derive(Clone)]
pub struct MerkleTreeTestParameters;

impl MerkleTreeParameters for MerkleTreeTestParameters {
    const DEPTH: usize = MERKLE_MEMORY_DEPTH;
}

impl<P: PortalManager<Fr>> Memory<'_, P> {
    pub fn get(&mut self, name: &str, cs: ConstraintSystemRef<Fr>) {
        match self.use_merkle_memory {
            true => {
                merkle_path_verification(cs.clone());
            },
            false => {
                let _ = self.portal_manager.get(name).expect("get error");
            },
        }
    }

    pub fn set(&mut self, name: String, value: &FpVar<Fr>, cs: ConstraintSystemRef<Fr>) {
        match self.use_merkle_memory {
            true => {
                merkle_path_verification(cs.clone());
                merkle_path_verification(cs.clone());
            },
            false => {
                let _ = self
                    .portal_manager
                    .set(name.parse().unwrap(), value)
                    .expect("set error");
            },
        }
    }
}

pub fn merkle_path_verification(cs: ConstraintSystemRef<Fr>) {
    // define the tree, leaf and leaf_h
    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;
    let mut tree = TestMerkleTree::new().unwrap();
    let leaf = [1_u8; 32];
    let leaf_hash = hash(&leaf).unwrap();

    // get index and insert it into the tree
    let index = SparseMerkleTree::<MerkleTreeTestParameters>::get_index(
        leaf_hash.as_slice(),
        MerkleTreeTestParameters::DEPTH,
    )
    .unwrap();
    tree.insert(index.clone(), &leaf, NodeType::Leaf).unwrap();

    // get the path
    let path = tree.lookup_path(&index).unwrap();

    // Allocate leaf
    let leaf_var = Vec::<UInt8<Fr>>::new_witness(cs.clone(), || Ok(leaf)).unwrap();

    // allocate index
    let mut fixed_size_array: [u8; 8] = [0; 8];
    fixed_size_array.copy_from_slice(&leaf_hash.as_slice()[0..8]);
    let index_var =
        UInt64::<Fr>::new_witness(cs.clone(), || Ok(u64::from_le_bytes(fixed_size_array)))
            .unwrap()
            .to_bits_le();

    // allocate path
    let path_var =
        MerkleTreePathVar::<MerkleTreeTestParameters>::new_witness(cs.clone(), || Ok(path))
            .unwrap();

    // do path verification
    let _ = path_var
        .compute_root_var_from_leaf(&leaf_var, &index_var)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use crate::vm::memory::merkle_path_verification;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_path_verification() {
        merkle_path_verification(ConstraintSystem::<Fr>::new_ref());
    }
}
