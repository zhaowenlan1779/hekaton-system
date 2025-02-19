use std::fmt::{Display, Formatter};
use std::ops::ShrAssign;
use std::{collections::HashMap, error::Error as ErrorTrait, fmt, marker::PhantomData};

use crate::vkd::hash::*;
use crate::vkd::util::split;
use ark_bls12_381::Fr;
use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};

const INITIAL_LEAF_VALUE: [u8; 32] = [0u8; 32];

// We model the array of the path as n BigUint and view it as a stream of bytes that it's meaningful for "depth" bits
#[derive(Eq, Hash, PartialEq, Clone, Debug, Default)]
pub struct MerkleIndex {
    pub index: BigUint,
    pub depth: usize,
}

impl MerkleIndex {
    // This bit vector is used by path verification function
    pub fn to_bit_vector(&self) -> Vec<bool> {
        let mut res = Vec::new();
        let depth = self.depth;
        let mut index = self.index.clone();
        for _d in (0..depth).rev() {
            if is_even(&index) {
                res.push(true);
            } else {
                res.push(false);
            }
            index = &index >> 1;
        }
        return res;
    }
}

// We use SHA256, our InnerHash is 31 bytes instead of 32 and outputs of constraints is Fp instead of Digest ==> output/input of hashes are Fp
pub type InnerHash = [u8; INNER_HASH_SIZE];
pub const INNER_HASH_SIZE: usize = 27;

pub trait MerkleTreeParameters {
    const DEPTH: usize;
}

#[derive(Clone)]
pub struct SparseMerkleTree<P: MerkleTreeParameters> {
    pub tree: HashMap<MerkleIndex, InnerHash>,
    pub leaves: HashMap<MerkleIndex, Vec<u8>>,
    pub root: InnerHash,
    pub sparse_initial_hashes: Vec<InnerHash>,
    _parameters1: PhantomData<P>,
    _parameters2: PhantomData<Fr>,
}

impl<P: MerkleTreeParameters> Display for SparseMerkleTree<P> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "(leaves: {:?})", self.leaves.keys())
    }
}

impl<P: MerkleTreeParameters> Default for SparseMerkleTree<P> {
    fn default() -> Self {
        SparseMerkleTree::new().unwrap()
    }
}

impl<P: MerkleTreeParameters> SparseMerkleTree<P> {
    pub fn new() -> Result<Self, Error> {
        // Compute initial hashes for each depth of tree
        let mut sparse_initial_hashes = vec![hash_leaf(&INITIAL_LEAF_VALUE)?];
        for i in 1..=P::DEPTH {
            let child_hash = sparse_initial_hashes[i - 1].clone();
            sparse_initial_hashes.push(hash_inner_node(&child_hash, &child_hash)?);
        }
        sparse_initial_hashes.reverse();

        Ok(SparseMerkleTree {
            tree: HashMap::new(),
            root: sparse_initial_hashes[0].clone(),
            leaves: HashMap::new(),
            sparse_initial_hashes,
            _parameters1: PhantomData,
            _parameters2: PhantomData,
        })
    }

    /*
    Function Overview:
        - This function inserts a leaf into the tree based on a given MerkleIndex.
        - Takes a node_type argument, which can be either Leaf or InternalNode:
           - Leaf: The initial value is hashed.
           - InternalNode: The value is treated as an internal node and cast to InnerHash.
        - Provides flexibility in handling different node types during tree updates.
     */
    pub fn insert(
        &mut self,
        index: MerkleIndex,
        value: &[u8],
        node_type: NodeType,
    ) -> Result<(), Error> {
        let i = &mut index.index.clone();
        // set the hash, based on node type, if it's already from internal nodes just output itself, else hash the given leaf
        let node_hash = match node_type {
            NodeType::InternalNode => InnerHash::try_from(value).unwrap(),
            NodeType::Leaf => {
                self.leaves.insert(index.clone(), value.to_vec());
                hash_leaf(value)?
            },
        };
        // insert the node inside the tree
        self.tree.insert(
            MerkleIndex {
                index: i.clone(),
                depth: index.depth,
            },
            node_hash,
        );

        for d in (0..index.depth).rev() {
            let _ = &i.shr_assign(1);
            let lc_i = &*i << 1;
            let rc_i = &lc_i + 1_u8;
            let lc_hash = self.lookup_internal_node(lc_i, d + 1).unwrap();
            let rc_hash = self.lookup_internal_node(rc_i, d + 1).unwrap();
            let temp = MerkleIndex {
                index: i.clone(),
                depth: d,
            };
            self.tree
                .insert(temp.clone(), hash_inner_node(&(lc_hash.0), &(rc_hash.0))?);
        }
        let temp = MerkleIndex {
            index: BigUint::zero(),
            depth: 0,
        };
        self.root = self.tree.get(&temp).expect("root lookup failed").clone();
        Ok(())
    }

    pub fn lookup_internal_node(
        &self,
        index: BigUint,
        depth: usize,
    ) -> Result<(InnerHash, bool), Error> {
        let res = match self.tree.get(&MerkleIndex { index, depth }) {
            Some(h) => (h.clone(), true),
            None => (self.sparse_initial_hashes[depth].clone(), false),
        };
        Ok(res)
    }

    pub fn lookup_path(&self, index: &MerkleIndex) -> Result<MerkleTreePath<P>, Error> {
        let mut path = Vec::new();
        let mut i = index.index.clone();
        for d in (1..=index.depth).rev() {
            let sibling_hash = self.lookup_internal_node(&i ^ BigUint::one(), d).unwrap().0;
            path.push(sibling_hash);
            i = i >> 1;
        }
        Ok(MerkleTreePath {
            path,
            _parameters1: PhantomData,
            _parameters2: PhantomData,
        })
    }

    pub fn get_index(leaf_h: &[u8], depth: usize) -> Result<MerkleIndex, Error> {
        if leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        let i = BigUint::from_bytes_le(&leaf_h[0..depth / 8]);
        Ok(MerkleIndex { index: i, depth })
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct MerkleTreePath<P: MerkleTreeParameters> {
    pub path: Vec<InnerHash>,
    // pretty smart to avoid multi-thread problems ==> https://stackoverflow.com/questions/50200197/how-do-i-share-a-struct-containing-a-phantom-pointer-among-threads
    pub _parameters1: PhantomData<fn() -> P>,
    pub _parameters2: PhantomData<fn() -> Fr>,
}

impl<P: MerkleTreeParameters> Clone for MerkleTreePath<P> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            _parameters1: PhantomData,
            _parameters2: PhantomData,
        }
    }
}

impl<P: MerkleTreeParameters> Default for MerkleTreePath<P> {
    fn default() -> Self {
        Self {
            path: vec![InnerHash::default(); P::DEPTH],
            _parameters1: PhantomData,
            _parameters2: PhantomData,
        }
    }
}

impl<P: MerkleTreeParameters> MerkleTreePath<P> {
    pub fn compute_root(
        &self,
        value: &[u8],
        index: &Vec<bool>,
        node_type: NodeType,
    ) -> Result<InnerHash, Error> {
        let mut current_hash = match node_type {
            NodeType::InternalNode => InnerHash::try_from(value).unwrap(),
            NodeType::Leaf => hash_leaf(value)?,
        };
        for (i, sibling_hash) in self.path.iter().enumerate() {
            current_hash = match index[i] {
                true => hash_inner_node(&current_hash, sibling_hash)?,
                false => hash_inner_node(sibling_hash, &current_hash)?,
            };
        }
        Ok(current_hash)
    }

    pub fn verify(
        &self,
        root: &InnerHash,
        value: &[u8],
        index: &Vec<bool>,
        node_type: NodeType,
    ) -> Result<bool, Error> {
        Ok(self.compute_root(value, index, node_type)? == *root)
    }
}

impl<P: MerkleTreeParameters> MerkleTreePath<P> {
    pub fn split(&self, split_factor: usize) -> Result<Vec<MerkleTreePath<P>>, Error> {
        let res = split(self.path.clone(), split_factor).unwrap();
        Ok(res
            .into_iter()
            .map(|path| MerkleTreePath {
                path,
                _parameters1: PhantomData,
                _parameters2: PhantomData,
            })
            .collect())
    }
}

pub enum NodeType {
    Leaf,
    InternalNode,
}

pub fn is_even(number: &BigUint) -> bool {
    number % 2_u8 == BigUint::zero()
}

#[derive(Debug)]
pub enum MerkleTreeError {
    TreeDepth(usize),
    LeafIndex(MerkleIndex),
    FullTree,
    InvalidHashSize,
    LeafNotFound,
    SHA256Collision,
    InvalidDepthInsertion,
    InvalidParameter,
}

impl ErrorTrait for MerkleTreeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl Display for MerkleTreeError {
    fn fmt(self: &Self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MerkleTreeError::TreeDepth(h) => format!("tree depth is invalid: {}", h),
            MerkleTreeError::LeafIndex(i) => format!("leaf index is invalid: {:?}", i),
            MerkleTreeError::FullTree => "tree already full (recurring leaf)".to_string(),
            MerkleTreeError::InvalidHashSize => "invalid hash size".to_string(),
            MerkleTreeError::LeafNotFound => "leaf not found".to_string(),
            MerkleTreeError::SHA256Collision => "sha256 collision".to_string(),
            MerkleTreeError::InvalidDepthInsertion => "invalid depth insertion".to_string(),
            MerkleTreeError::InvalidParameter => "invalid parameters".to_string(),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: usize = 64;
    }

    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;

    #[test]
    fn insert_test() {
        let mut merkle_tree = TestMerkleTree::new().unwrap();
        let first_leaf = [1_u8; 32];
        let first_index = SparseMerkleTree::<MerkleTreeTestParameters>::get_index(
            &first_leaf,
            MerkleTreeTestParameters::DEPTH,
        )
        .unwrap();

        // update the tree
        merkle_tree
            .insert(first_index.clone(), &first_leaf, NodeType::Leaf)
            .expect("insertion error");
        let path_to_first_leaf = merkle_tree.lookup_path(&first_index).unwrap();
        assert!(path_to_first_leaf
            .verify(
                &merkle_tree.root,
                &first_leaf,
                &first_index.to_bit_vector(),
                NodeType::Leaf,
            )
            .expect("path verification error"));

        let second_leaf = [9_u8; 32];
        let second_index = SparseMerkleTree::<MerkleTreeTestParameters>::get_index(
            &second_leaf,
            MerkleTreeTestParameters::DEPTH,
        )
        .unwrap();

        // update the tree
        merkle_tree
            .insert(second_index.clone(), &second_leaf, NodeType::Leaf)
            .expect("insertion error");
        let path_to_second_leaf = merkle_tree.lookup_path(&second_index).unwrap();
        assert!(path_to_second_leaf
            .verify(
                &merkle_tree.root,
                &second_leaf,
                &second_index.to_bit_vector(),
                NodeType::Leaf,
            )
            .expect("path verification error"));

        let third_leaf = [10_u8; 32];
        let third_leaf_hash = hash_leaf(&third_leaf).unwrap();
        let third_index = SparseMerkleTree::<MerkleTreeTestParameters>::get_index(
            &third_leaf,
            MerkleTreeTestParameters::DEPTH,
        )
        .unwrap();

        // update the tree
        merkle_tree
            .insert(third_index.clone(), &third_leaf, NodeType::Leaf)
            .expect("insertion error");

        let path_to_third_leaf = merkle_tree.lookup_path(&third_index).unwrap();

        assert!(path_to_third_leaf
            .verify(
                &merkle_tree.root,
                &third_leaf_hash,
                &third_index.to_bit_vector(),
                NodeType::InternalNode,
            )
            .expect("path verification error"));
        println!("{}", merkle_tree);
    }

    #[test]
    fn test_split() {
        let mut merkle_tree = TestMerkleTree::new().unwrap();
        let first_leaf = [1_u8; 32];
        let first_index = SparseMerkleTree::<MerkleTreeTestParameters>::get_index(
            &first_leaf,
            MerkleTreeTestParameters::DEPTH,
        )
        .unwrap();
        // update the tree
        merkle_tree
            .insert(first_index.clone(), &first_leaf, NodeType::Leaf)
            .expect("insertion error");
        let path_to_first_leaf = merkle_tree.lookup_path(&first_index).unwrap();
        let split_path = path_to_first_leaf.split(2).unwrap();
        println!("{:?}", path_to_first_leaf.path);
        for split in split_path.iter() {
            println!("{:?}", split.path);
        }
    }
}
