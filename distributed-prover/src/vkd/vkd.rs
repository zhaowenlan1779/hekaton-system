use std::collections::HashMap;
use std::fmt::Display;

use crate::vkd::hash::hash;
use crate::vkd::sparse_tree::{
    InnerHash, MerkleTreeParameters, MerkleTreePath, NodeType, SparseMerkleTree,
};
use crate::vkd::vkd_circuits::*;
use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::seq::IteratorRandom;
use rand::thread_rng;

/*
 * SECTION 1: DEFINE VKD AND ITS RELEVANT FUNCTIONS
 */

pub type Username = [u8; 32];
pub type Key = [u8; 32];
pub type Counter = u16;
pub type Leaf = [u8; 66];

pub fn default_leaf() -> Leaf {
    <Leaf>::try_from([0u8; 66]).unwrap()
}

// DEPTH is among [8, 16, 32, 64, 128, 256]
pub const DEPTH: usize = 128;
pub(crate) const SPLIT_FACTOR: usize = 4;
// A power of two such that DEPTH / SPLIT_FACTOR >= 8
pub(crate) const PATH_LENGTH: usize = DEPTH / SPLIT_FACTOR;

#[derive(Clone, Debug, PartialEq)]
pub struct MerkleTreeConcreteParameters;

impl MerkleTreeParameters for MerkleTreeConcreteParameters {
    const DEPTH: usize = DEPTH;
}

// Very high-level it seems VerifiableKeyDirectoryCircuit takes arguments for an initial root and final root and one update
// It checks that the updates actually end us up with that final tree
#[derive(Clone)]
pub struct VerifiableKeyDirectoryCircuit {
    pub(crate) initial_root: InnerHash,
    pub(crate) params: VerifiableKeyDirectoryCircuitParams,
    pub(crate) final_root: InnerHash,
    pub(crate) update: Vec<Update>,
    pub(crate) subcircuits: Vec<SubCircuit>,
}

#[derive(Clone, Debug)]
pub enum Update {
    Update(VkdUpdate),
    Append(VkdAppend),
}

// e.g. (Alice, ctr, key) ==> (Alice, ctr + 1, key')
#[derive(Clone, Debug)]
pub struct VkdUpdate {
    pub(crate) username: Username,
    pub(crate) counter: Counter,
    pub(crate) key1: Key,
    pub(crate) path: MerkleTreePath<MerkleTreeConcreteParameters>,
    pub(crate) key2: Key,
}

// add (Alice, 0, key)
#[derive(Clone, Debug)]
pub struct VkdAppend {
    pub(crate) username: Username,
    pub(crate) key: Key,
    pub(crate) path: MerkleTreePath<MerkleTreeConcreteParameters>,
}

impl Default for VkdUpdate {
    fn default() -> Self {
        VkdUpdate {
            username: Username::default(),
            counter: Counter::default(),
            key1: Key::default(),
            path: MerkleTreePath::default(),
            key2: Key::default(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableKeyDirectoryCircuitParams {
    /// Num of updates
    pub log_num_subcircuits: usize,
    /// the null leaf
    pub null_leaf: InnerHash,
}

impl Display for VerifiableKeyDirectoryCircuitParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[nu={}]", self.log_num_subcircuits)
    }
}

pub fn concat(username: Username, key: Key, counter: Counter) -> Vec<u8> {
    let mut username_vec = Vec::from(username);
    let key_vec = Vec::from(key);
    username_vec.extend(&counter.to_le_bytes());
    username_vec.extend(key_vec);
    username_vec
}

pub fn get_random_key_value<K, V>(users: &HashMap<K, V>) -> Option<(K, V)>
where
    K: Clone,
    V: Clone,
{
    let mut rng = thread_rng();
    users
        .iter()
        .choose(&mut rng)
        .map(|(key, value)| (key.clone(), value.clone()))
}

impl VerifiableKeyDirectoryCircuit {
    pub fn random(params: &VerifiableKeyDirectoryCircuitParams) -> VerifiableKeyDirectoryCircuit {
        // generate the initial tree from a random bytes
        let mut tree = SparseMerkleTree::new().unwrap();
        // usernames
        let mut users = HashMap::new();
        // add the initial (genesis) user
        users.insert(Username::default(), (0, Key::default()));
        let temp = concat(Username::default(), Key::default(), 0);
        let leaf_h = hash(Username::default().as_slice()).unwrap();
        let index = SparseMerkleTree::<MerkleTreeConcreteParameters>::get_index(
            leaf_h.as_slice(),
            MerkleTreeConcreteParameters::DEPTH,
        )
        .unwrap();
        tree.insert(index.clone(), temp.as_slice(), NodeType::Leaf)
            .expect("insertion panic");
        // initial root
        let initial_root = tree.root.clone();
        // generate random updates
        let mut updates: Vec<Update> = Vec::new();
        let num_of_updates = (((1 << params.log_num_subcircuits) - 8) / 8) - 1;
        let num_of_appends = 0;
        // first update
        let username = [8u8; 32] as Username;
        let key = [0u8; 32] as Key;
        users.insert(username, (0, key));
        // add it to the tree
        let leaf_h = hash(username.as_slice()).unwrap();
        let index = SparseMerkleTree::<MerkleTreeConcreteParameters>::get_index(
            leaf_h.as_slice(),
            MerkleTreeConcreteParameters::DEPTH,
        )
        .unwrap();
        let path = tree.lookup_path(&index).unwrap();
        // append it the tree
        tree.insert(
            index.clone(),
            concat(username, key, 0).as_slice(),
            NodeType::Leaf,
        )
        .expect("insertion panic");
        // add the update to the vector of all updates
        updates.push(Update::Append(VkdAppend {
            username,
            key,
            path,
        }));
        // rest
        for i in 0usize..num_of_updates + num_of_appends {
            // indicate if you want to append a new key or update
            if i < num_of_updates {
                // randomly choose on of the usernames
                let (counter, key1) = &users.get(&username).unwrap().clone();
                // gets its path from the tree
                let leaf_h = hash(username.as_slice()).unwrap();
                let index = SparseMerkleTree::<MerkleTreeConcreteParameters>::get_index(
                    leaf_h.as_slice(),
                    MerkleTreeConcreteParameters::DEPTH,
                )
                .unwrap();
                let path = tree.lookup_path(&index).unwrap();
                // choose a new key
                let key2 = [(i % 256) as u8; 32];
                let new_counter = counter + 1;
                users.insert(username, (new_counter, key2));
                // get the new path
                tree.insert(
                    index.clone(),
                    concat(username, key2, new_counter).as_slice(),
                    NodeType::Leaf,
                )
                .expect("insertion panic");
                // add the update to the vector of all updates
                let u = VkdUpdate {
                    username,
                    counter: *counter,
                    key1: *key1,
                    path,
                    key2,
                };
                updates.push(Update::Update(u));
            }
        }
        // let subcircuits = vkd_update_to_subcircuit(&updates);
        // get the final tree by updates
        VerifiableKeyDirectoryCircuit {
            initial_root,
            params: params.clone(),
            final_root: tree.root.clone(),
            update: updates.clone(),
            subcircuits: vkd_update_to_subcircuit(&updates),
        }
    }

    pub fn verify(&self, pp: InnerHash) -> Result<bool, Error> {
        let mut res = true;
        // compute the final root wrt updates and check if it's equal to the supposed one
        let mut root = self.initial_root;
        for (i, u) in self.update.iter().enumerate() {
            match u {
                Update::Update(op) => {
                    // first key exists in the tree
                    let leaf_h = hash(op.username.as_slice()).unwrap();
                    let index = SparseMerkleTree::<MerkleTreeConcreteParameters>::get_index(
                        leaf_h.as_slice(),
                        MerkleTreeConcreteParameters::DEPTH,
                    )
                    .unwrap();
                    res = res
                        & op.path
                            .verify(
                                &root,
                                concat(op.username, op.key1, op.counter).as_slice(),
                                &index.to_bit_vector(),
                                NodeType::Leaf,
                            )
                            .unwrap();
                    // update the root to add the update
                    root = op
                        .path
                        .compute_root(
                            concat(op.username, op.key2, op.counter + 1).as_slice(),
                            &index.to_bit_vector(),
                            NodeType::Leaf,
                        )
                        .unwrap();
                    println!("{} {}", res, i);
                },
                Update::Append(op) => {
                    // append it to the tree
                    let leaf_h = hash(op.username.as_slice()).unwrap();
                    let index = SparseMerkleTree::<MerkleTreeConcreteParameters>::get_index(
                        leaf_h.as_slice(),
                        MerkleTreeConcreteParameters::DEPTH,
                    )
                    .unwrap();
                    res = res
                        & op.path
                            .verify(&root, &pp, &index.to_bit_vector(), NodeType::InternalNode)
                            .unwrap();
                    root = op
                        .path
                        .compute_root(
                            concat(op.username, op.key, 0).as_slice(),
                            &index.to_bit_vector(),
                            NodeType::Leaf,
                        )
                        .unwrap();
                    println!("{} {}", res, i);
                },
            }
        }
        Ok((root == self.final_root) & res)
    }

    // Function to count Appends and Updates
    pub fn count_appends_updates(&self) -> (usize, usize) {
        let mut append_count = 0;
        let mut update_count = 0;

        for update in &self.update {
            match update {
                Update::Update(_) => update_count += 1,
                Update::Append(_) => append_count += 1,
            }
        }

        (append_count, update_count)
    }
}

/*
 * SECTION 2: DEFINE FUNCTION TO INITIALISE SUBCIRCUITS
 */

pub fn get_previous_root_from_update_idx(update_idx: usize, updates: &Vec<Update>) -> NodeAddress {
    // initial node
    if update_idx == 0 {
        return NodeAddress::InitialRoot(InitialRootAddress {});
    }
    // the rest
    let u = &updates[update_idx - 1];
    return match u {
        Update::Update(_) => NodeAddress::PathRoot(PathRootAddress {
            path_id: 1,
            update_idx: update_idx - 1,
        }),
        Update::Append(_) => NodeAddress::PathRoot(PathRootAddress {
            path_id: 1,
            update_idx: update_idx - 1,
        }),
    };
}

pub fn get_node_addresses(
    update_idx: usize,
    path_id: usize,
    initial_node: NodeAddress,
) -> Vec<(NodeAddress, NodeAddress)> {
    let mut res = Vec::new();
    for i in 0..SPLIT_FACTOR {
        if i == 0 {
            let root = NodeAddress::IntermediateRoot(IntermediateRootAddress {
                //input: false,
                indicator: i,
                path_id,
                update_idx,
            });
            res.push((initial_node.clone(), root))
        } else if i == (SPLIT_FACTOR - 1) {
            let root1 = NodeAddress::IntermediateRoot(IntermediateRootAddress {
                //input: true,
                indicator: i - 1,
                path_id,
                update_idx,
            });
            let root2 = NodeAddress::PathRoot(PathRootAddress {
                path_id,
                update_idx,
            });
            res.push((root1, root2))
        } else {
            let root1 = NodeAddress::IntermediateRoot(IntermediateRootAddress {
                //input: true,
                indicator: i - 1,
                path_id,
                update_idx,
            });
            let root2 = NodeAddress::IntermediateRoot(IntermediateRootAddress {
                //input: false,
                indicator: i,
                path_id,
                update_idx,
            });
            res.push((root1, root2))
        }
    }
    res
}

pub fn vkd_update_to_subcircuit(updates: &Vec<Update>) -> Vec<SubCircuit> {
    let mut subcircuits = Vec::new();

    // 6 paddings
    for _i in 0..6 {
        let compound_primitive_vec =
            vec![PrimitiveSubcircuit::PaddingPrimitive(PaddingPrimitive {})];
        subcircuits.push(SubCircuit {
            compound_primitive_vec,
        });
    }

    // write pp
    let compound_primitive_vec = vec![PrimitiveSubcircuit::WritePublicParameterPrimitive(
        WritePublicParameterPrimitive {},
    )];
    subcircuits.push(SubCircuit {
        compound_primitive_vec,
    });

    // iterating through all the updates
    for (update_idx, u) in updates.iter().enumerate() {
        match u {
            Update::Update(u) => {
                let leaf1 = concat(u.username, u.key1, u.counter);
                // we need one subcircuit to compute the root
                for i in 0..SPLIT_FACTOR {
                    let path_id = 0usize;
                    let node_vector = get_node_addresses(
                        update_idx,
                        path_id,
                        NodeAddress::LeafHash(LeafHashAddress {
                            leaf: Leaf::try_from(leaf1.clone()).unwrap(),
                        }),
                    );
                    let split_path = u.path.split(SPLIT_FACTOR).unwrap();

                    let op = ComputePathPrimitive {
                        update_idx,
                        path_id,
                        indicator: i,
                        initial_value_addr: NodeAddressBytes::node_address_to_bytes(
                            node_vector[i].0.clone(),
                        ),
                        final_value_addr: NodeAddressBytes::node_address_to_bytes(
                            node_vector[i].1.clone(),
                        ),
                        index_addr: IndexAddress {
                            indicator: i,
                            leaf: <Leaf>::try_from(leaf1.clone()).unwrap(),
                        },
                        path: split_path[i].clone(),
                    };
                    subcircuits.push(SubCircuit {
                        compound_primitive_vec: vec![PrimitiveSubcircuit::ComputePathPrimitive(op)],
                    });
                }

                let mut c = SubCircuit {
                    compound_primitive_vec: vec![PrimitiveSubcircuit::EqualityPrimitive(
                        EqualityPrimitive {
                            update_idx,
                            addr1: NodeAddressBytes::node_address_to_bytes(NodeAddress::PathRoot(
                                PathRootAddress {
                                    path_id: 0,
                                    update_idx,
                                },
                            )),
                            addr2: NodeAddressBytes::node_address_to_bytes(
                                get_previous_root_from_update_idx(update_idx, updates),
                            ),
                        },
                    )],
                };

                let leaf2 = concat(u.username, u.key2, u.counter + 1);
                // hash leaf subcircuit to compute hash of the leaf
                c.compound_primitive_vec
                    .push(PrimitiveSubcircuit::HashLeafPrimitive(HashLeafPrimitive {
                        leaf: <Leaf>::try_from(leaf2.clone()).unwrap(),
                    }));

                // we need one subcircuit to compute the root
                for i in 0..SPLIT_FACTOR {
                    let path_id = 1usize;
                    let node_vector = get_node_addresses(
                        update_idx,
                        path_id,
                        NodeAddress::LeafHash(LeafHashAddress {
                            leaf: Leaf::try_from(leaf2.clone()).unwrap(),
                        }),
                    );
                    let split_path = u.path.split(SPLIT_FACTOR).unwrap();
                    let subcircuit =
                        PrimitiveSubcircuit::ComputePathPrimitive(ComputePathPrimitive {
                            update_idx,
                            path_id,
                            indicator: i,
                            initial_value_addr: NodeAddressBytes::node_address_to_bytes(
                                node_vector[i].0.clone(),
                            ),
                            final_value_addr: NodeAddressBytes::node_address_to_bytes(
                                node_vector[i].1.clone(),
                            ),
                            index_addr: IndexAddress {
                                indicator: i,
                                leaf: <Leaf>::try_from(leaf1.clone()).unwrap(),
                            },
                            path: split_path[i].clone(),
                        });
                    if i == 0 {
                        c.compound_primitive_vec.push(subcircuit.clone());
                        subcircuits.push(c.clone());
                    } else {
                        subcircuits.push(SubCircuit {
                            compound_primitive_vec: vec![subcircuit],
                        });
                    }
                }
            },
            Update::Append(u) => {
                let leaf = concat(u.username, u.key, 0);

                // hash leaf subcircuit to compute hash of the leaf
                let mut c = SubCircuit {
                    compound_primitive_vec: vec![PrimitiveSubcircuit::HashLeafPrimitive(
                        HashLeafPrimitive {
                            leaf: <Leaf>::try_from(leaf.clone()).unwrap(),
                        },
                    )],
                };

                // index subcircuit to compute index of the leaf
                c.compound_primitive_vec
                    .push(PrimitiveSubcircuit::GetIndexPrimitive(GetIndexPrimitive {
                        update_idx,
                        leaf: <Leaf>::try_from(leaf.clone()).unwrap(),
                    }));

                let mut last = SubCircuit {
                    compound_primitive_vec: vec![],
                };
                // we need one subcircuit to compute the root vs null leaf
                for i in 0..SPLIT_FACTOR {
                    let path_id = 0;
                    let node_vector = get_node_addresses(
                        update_idx,
                        path_id,
                        NodeAddress::NullLeaf(NullLeafAddress {}),
                    );
                    let split_path = u.path.split(SPLIT_FACTOR).unwrap();
                    let op = ComputePathPrimitive {
                        update_idx,
                        path_id,
                        indicator: i,
                        initial_value_addr: NodeAddressBytes::node_address_to_bytes(
                            node_vector[i].0.clone(),
                        ),
                        final_value_addr: NodeAddressBytes::node_address_to_bytes(
                            node_vector[i].1.clone(),
                        ),
                        index_addr: IndexAddress {
                            indicator: i,
                            leaf: <Leaf>::try_from(leaf.clone()).unwrap(),
                        },
                        path: split_path[i].clone(),
                    };
                    if i == 0 {
                        c.compound_primitive_vec
                            .push(PrimitiveSubcircuit::ComputePathPrimitive(op));
                        subcircuits.push(c.clone());
                    } else if i == SPLIT_FACTOR - 1 {
                        last = SubCircuit {
                            compound_primitive_vec: vec![
                                PrimitiveSubcircuit::ComputePathPrimitive(op),
                            ],
                        };
                    } else {
                        subcircuits.push(SubCircuit {
                            compound_primitive_vec: vec![
                                PrimitiveSubcircuit::ComputePathPrimitive(op),
                            ],
                        });
                    }
                }

                // equality subcircuit to make sure it's equal to the initial root
                last.compound_primitive_vec
                    .push(PrimitiveSubcircuit::EqualityPrimitive(EqualityPrimitive {
                        update_idx,
                        addr1: NodeAddressBytes::node_address_to_bytes(NodeAddress::PathRoot(
                            PathRootAddress {
                                path_id: 0,
                                update_idx,
                            },
                        )),
                        addr2: NodeAddressBytes::node_address_to_bytes(
                            get_previous_root_from_update_idx(update_idx, updates),
                        ),
                    }));
                subcircuits.push(last);

                // we need one subcircuit to compute the root vs null leaf
                for i in 0..SPLIT_FACTOR {
                    let path_id = 1usize;
                    let node_vector = get_node_addresses(
                        update_idx,
                        path_id,
                        NodeAddress::LeafHash(LeafHashAddress {
                            leaf: Leaf::try_from(leaf.clone()).unwrap(),
                        }),
                    );
                    let split_path = u.path.split(SPLIT_FACTOR).unwrap();

                    subcircuits.push(SubCircuit {
                        compound_primitive_vec: vec![PrimitiveSubcircuit::ComputePathPrimitive(
                            ComputePathPrimitive {
                                update_idx,
                                path_id,
                                indicator: i,
                                initial_value_addr: NodeAddressBytes::node_address_to_bytes(
                                    node_vector[i].0.clone(),
                                ),
                                final_value_addr: NodeAddressBytes::node_address_to_bytes(
                                    node_vector[i].1.clone(),
                                ),
                                index_addr: IndexAddress {
                                    indicator: i,
                                    leaf: <Leaf>::try_from(leaf.clone()).unwrap(),
                                },
                                path: split_path[i].clone(),
                            },
                        )],
                    });
                }
            },
        }
    }

    // equality subcircuit to make sure it's equal to the final root
    subcircuits.push(SubCircuit {
        compound_primitive_vec: vec![PrimitiveSubcircuit::EqualityPrimitive(EqualityPrimitive {
            update_idx: updates.len() - 1,
            addr1: NodeAddressBytes::node_address_to_bytes(NodeAddress::FinalRoot(
                FinalRootAddress {},
            )),
            addr2: NodeAddressBytes::node_address_to_bytes(get_previous_root_from_update_idx(
                updates.len(),
                &updates,
            )),
        })],
    });

    // return the result
    subcircuits
}

#[cfg(test)]
mod tests {
    use crate::vkd::{
        MerkleTreeConcreteParameters, SparseMerkleTree, VerifiableKeyDirectoryCircuit,
        VerifiableKeyDirectoryCircuitParams, DEPTH,
    };

    #[test]
    fn test_vkd_rand() {
        type TestMerkleTree = SparseMerkleTree<MerkleTreeConcreteParameters>;
        let tree = TestMerkleTree::new().unwrap();

        let circ_params = VerifiableKeyDirectoryCircuitParams {
            // 5 <= log_num_subcircuits <= 50
            log_num_subcircuits: 5,
            null_leaf: tree.sparse_initial_hashes[DEPTH],
        };
        let vkd: VerifiableKeyDirectoryCircuit =
            VerifiableKeyDirectoryCircuit::random(&circ_params);
        assert!(vkd.verify(tree.sparse_initial_hashes[DEPTH]).unwrap());
    }
}
