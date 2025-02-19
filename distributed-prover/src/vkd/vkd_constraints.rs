use crate::portal_manager::{PortalManager, RomProverPortalManager, SetupRomPortalManager};
use crate::transcript::{MemType, TranscriptEntry};
use crate::vkd::hash::{hash, hash_leaf, hash_leaf_var, hash_var};
use crate::vkd::util::*;
use crate::vkd::{
    vkd_update_to_subcircuit, FinalRootAddress, IndexAddress, InitialRootAddress, InnerHash,
    LeafHashAddress, MerkleTreeConcreteParameters, MerkleTreePathVar, NodeAddressBytes, NodeType,
    NullLeafAddress, PrimitiveSubcircuit, SubcircuitBytes, VerifiableKeyDirectoryCircuit,
    VerifiableKeyDirectoryCircuitParams, DEPTH, SPLIT_FACTOR,
};
use crate::CircuitWithPortals;
use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use lazy_static::lazy_static;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct VKDCache {
    circuits: Mutex<HashMap<VerifiableKeyDirectoryCircuitParams, VerifiableKeyDirectoryCircuit>>,
}

impl VKDCache {
    pub fn new() -> Self {
        VKDCache {
            circuits: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_or_init(
        &self,
        params: VerifiableKeyDirectoryCircuitParams,
    ) -> VerifiableKeyDirectoryCircuit {
        let mut circuits = self.circuits.lock().unwrap();
        circuits
            .entry(params.clone())
            .or_insert_with(|| VerifiableKeyDirectoryCircuit::random(&params))
            .clone()
    }
}

lazy_static! {
    static ref CIRCUIT_CACHE: VKDCache = VKDCache::new();
}

// InnerHash <====> UInt8 <== digest_to_fpvar ==> FpVar
impl CircuitWithPortals<Fr> for VerifiableKeyDirectoryCircuit {
    type Parameters = VerifiableKeyDirectoryCircuitParams;
    type ProverPortalManager = RomProverPortalManager<Fr>;
    const MEM_TYPE: MemType = MemType::Rom;

    /// Makes a random instance of this circuit with the given parameters
    fn rand(_rng: &mut impl Rng, params: &VerifiableKeyDirectoryCircuitParams) -> Self {
        VerifiableKeyDirectoryCircuit::random(params)
    }

    fn get_params(&self) -> VerifiableKeyDirectoryCircuitParams {
        self.params
    }

    // This produces the same portal trace as generate_constraints(0...num_circuits) would do, but
    // without having to do all the ZK SHA2 computations
    fn get_portal_subtraces(&self) -> Vec<Vec<TranscriptEntry<Fr>>> {
        // make a portal manager to collect the subtraces
        let cs = ConstraintSystem::new_ref();
        let mut pm = SetupRomPortalManager::new(cs.clone());
        // make memories for non-ZK computation
        let mut index_memory: HashMap<String, Vec<bool>> = HashMap::new();
        let mut inner_node_memory: HashMap<String, InnerHash> = HashMap::new();
        // get subcircuit vector
        let subcircuits = vkd_update_to_subcircuit(&self.update);
        for subcircuit in subcircuits.iter() {
            pm.start_subtrace(ConstraintSystem::new_ref());
            for primitive in &subcircuit.compound_primitive_vec {
                match primitive {
                    PrimitiveSubcircuit::WritePublicParameterPrimitive(_) => {
                        // set initial root and null root and final root
                        let addr = InitialRootAddress {}.to_string();
                        inner_node_memory.insert(addr, self.initial_root);
                        let addr = FinalRootAddress {}.to_string();
                        inner_node_memory.insert(addr, self.final_root);
                        let addr = NullLeafAddress {}.to_string();
                        inner_node_memory.insert(addr, self.params.null_leaf);

                        // update portal manager
                        let root_var =
                            UInt8::new_witness_vec(cs.clone(), &self.initial_root).unwrap();
                        let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                        let addr = InitialRootAddress {}.to_string();
                        let _ = pm.set(addr, &root_fpvar).unwrap();
                        let root_var =
                            UInt8::new_witness_vec(cs.clone(), &self.final_root).unwrap();
                        let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                        let addr = FinalRootAddress {}.to_string();
                        let _ = pm.set(addr, &root_fpvar).unwrap();
                        let root_var =
                            UInt8::new_witness_vec(cs.clone(), &self.params.null_leaf).unwrap();
                        let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                        let addr = NullLeafAddress {}.to_string();
                        let _ = pm.set(addr, &root_fpvar).unwrap();
                    },

                    PrimitiveSubcircuit::EqualityPrimitive(eq) => {
                        let addr1 = NodeAddressBytes::bytes_to_node_address(eq.clone().addr1);
                        let addr2 = NodeAddressBytes::bytes_to_node_address(eq.clone().addr2);
                        let _ = pm.get(&addr1.to_string()).unwrap();
                        let _ = pm.get(&addr2.to_string()).unwrap();
                        // no computation is required
                    },

                    // TODO: it works only for depth of less than 128
                    PrimitiveSubcircuit::GetIndexPrimitive(ind) => {
                        // set index_memory in non-ZK
                        let leaf_h = hash(&ind.leaf[0..32]).unwrap();
                        let index_vector = hash_leaf_to_split_index::<MerkleTreeConcreteParameters>(
                            leaf_h.as_slice(),
                            cs.clone(),
                            AllocationMode::Witness,
                            SPLIT_FACTOR,
                        );
                        for i in 0..SPLIT_FACTOR {
                            let addr = IndexAddress {
                                indicator: i,
                                leaf: ind.leaf,
                            }
                            .to_string();
                            index_memory.insert(addr.clone(), index_vector.1[i].clone());
                            let _ = pm.set(addr.clone(), &index_vector.0[i]).unwrap();
                        }
                    },

                    PrimitiveSubcircuit::ComputePathPrimitive(p) => {
                        let initial_value_addr =
                            NodeAddressBytes::bytes_to_node_address(p.initial_value_addr.clone());
                        // retrieve initial_value and index from memory and compute the root
                        let index = index_memory.get(&p.index_addr.to_string()).unwrap();
                        let initial_value = inner_node_memory
                            .get(&initial_value_addr.to_string())
                            .unwrap();
                        // call portal manager to retrieve values too
                        let _ = pm.get(&initial_value_addr.to_string()).unwrap();
                        let _ = pm.get(&p.index_addr.to_string()).unwrap();

                        // compute the root
                        let root = p
                            .path
                            .compute_root(initial_value, index, NodeType::InternalNode)
                            .unwrap();
                        let final_value_addr =
                            NodeAddressBytes::bytes_to_node_address(p.final_value_addr.clone());
                        inner_node_memory.insert(final_value_addr.to_string(), root.clone());
                        let root_var = UInt8::new_witness_vec(cs.clone(), &root).unwrap();
                        let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                        // Set the value
                        let _ = pm.set(final_value_addr.to_string(), &root_fpvar).unwrap();
                    },

                    PrimitiveSubcircuit::HashLeafPrimitive(h) => {
                        // set leaf_hash_memory
                        let leaf_h = hash_leaf(&h.leaf).unwrap();
                        let addr = LeafHashAddress { leaf: h.leaf }.to_string();
                        inner_node_memory.insert(addr, leaf_h);
                        // set portal manager
                        let leaf_h_var = UInt8::new_witness_vec(cs.clone(), &leaf_h).unwrap();
                        let leaf_h_fpvar = digest_to_fpvar(DigestVar(leaf_h_var)).unwrap();
                        let addr = LeafHashAddress { leaf: h.leaf }.to_string();
                        let _ = pm.set(addr, &leaf_h_fpvar).unwrap();
                    },

                    PrimitiveSubcircuit::PaddingPrimitive(_) => {},
                }
            }
        }
        // We don't compute any portal wires for the equality circuit

        // Return the subtraces, wrapped appropriately
        pm.subtraces
            .into_iter()
            .map(|subtrace| {
                subtrace
                    .into_iter()
                    .map(|e| TranscriptEntry::Rom(e))
                    .collect()
            })
            .collect()
    }

    fn num_subcircuits(&self) -> usize {
        1 << self.params.log_num_subcircuits
    }

    fn get_unique_subcircuits(&self) -> Vec<usize> {
        vec![0, 6, 7, 8, 10, 19, self.num_subcircuits() - 1]
    }

    fn representative_subcircuit(&self, subcircuit_idx: usize) -> usize {
        match self.subcircuits[subcircuit_idx].get_type().as_str() {
            "padding" => 0,
            "write pp" => 6,
            "hash leaf, get index, compute path" => 7,
            "compute path" => 8,
            "compute path, equality" => 10,
            "equality, hash leaf, compute path" => 19,
            "equality" => self.num_subcircuits() - 1,
            _ => panic!("shouldn't be here"),
        }
    }

    // Make a new empty VKD
    fn new(&params: &Self::Parameters) -> Self {
        CIRCUIT_CACHE.get_or_init(params)
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        let mut out_buf = Vec::new();
        let subcircuit_bytes =
            SubcircuitBytes::subcircuit_to_bytes(&self.subcircuits[subcircuit_idx]);
        subcircuit_bytes
            .serialize_uncompressed(&mut out_buf)
            .unwrap();
        out_buf
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        let subcircuit_byte = SubcircuitBytes::deserialize_uncompressed_unchecked(bytes).unwrap();
        let subcircuit = SubcircuitBytes::bytes_to_subcircuit(subcircuit_byte);
        self.subcircuits[subcircuit_idx] = subcircuit;
    }

    fn generate_constraints<P: PortalManager<Fr>>(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let starting_num_constraints = cs.num_constraints();
        let subcircuit = &self.subcircuits[subcircuit_idx];
        for primitive in &subcircuit.compound_primitive_vec {
            match primitive {
                PrimitiveSubcircuit::EqualityPrimitive(eq) => {
                    let addr1 = NodeAddressBytes::bytes_to_node_address(eq.clone().addr1);
                    let addr2 = NodeAddressBytes::bytes_to_node_address(eq.clone().addr2);
                    let value1 = pm.get(&addr1.to_string()).unwrap();
                    let value2 = pm.get(&addr2.to_string()).unwrap();
                    // check the equality
                    value1.enforce_equal(&value2).unwrap();
                },
                PrimitiveSubcircuit::GetIndexPrimitive(ind) => {
                    let leaf_var =
                        UInt8::new_witness_vec(cs.clone(), &ind.leaf[0..32].to_vec()).unwrap();
                    let hash = hash_var(&leaf_var).unwrap();
                    let sub_hash = &hash.to_bits_le().unwrap()[0..DEPTH];
                    let bool_vec = split(sub_hash.to_vec(), SPLIT_FACTOR).unwrap();

                    // assert equality
                    for i in 0..SPLIT_FACTOR {
                        let index = Boolean::le_bits_to_fp_var(bool_vec[i].as_slice()).unwrap();
                        let _ = pm
                            .set(
                                IndexAddress {
                                    indicator: i,
                                    leaf: ind.leaf,
                                }
                                .to_string(),
                                &index,
                            )
                            .unwrap();
                    }
                },
                PrimitiveSubcircuit::ComputePathPrimitive(p) => {
                    let initial_value_addr =
                        NodeAddressBytes::bytes_to_node_address(p.initial_value_addr.clone());
                    // retrieve initial node, final node and index from the portal manager
                    let initial_node = pm.get(&initial_value_addr.to_string()).unwrap();
                    let index_fpvar = pm.get(&p.index_addr.to_string()).unwrap();
                    let index = fpvar_to_boolean_index(index_fpvar).unwrap();

                    // add path as private input
                    let path_var = MerkleTreePathVar::<MerkleTreeConcreteParameters>::new_witness(
                        cs.clone(),
                        || Ok(&p.path),
                    )
                    .unwrap();

                    // assert validity
                    let root = path_var
                        .compute_root_var_from_internal_node(&initial_node, &index)
                        .unwrap();

                    // set root
                    let final_value_addr =
                        NodeAddressBytes::bytes_to_node_address(p.final_value_addr.clone());
                    let _ = pm.set(final_value_addr.to_string(), &root);
                },
                PrimitiveSubcircuit::HashLeafPrimitive(h) => {
                    // retrieve hash of leaf from memory
                    let leaf_addr = LeafHashAddress { leaf: h.leaf }.to_string();

                    // compute hash of leaf (witness)
                    let leaf_var = UInt8::new_witness_vec(cs.clone(), &h.leaf.to_vec()).unwrap();
                    let hash = hash_leaf_var(&leaf_var).unwrap();

                    // assert equality
                    let _ = pm.set(leaf_addr, &hash);
                },
                PrimitiveSubcircuit::WritePublicParameterPrimitive(_) => {
                    let root_var = UInt8::new_witness_vec(cs.clone(), &self.initial_root).unwrap();
                    let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                    let addr = InitialRootAddress {}.to_string();
                    let _ = pm.set(addr, &root_fpvar).unwrap();
                    let root_var = UInt8::new_witness_vec(cs.clone(), &self.final_root).unwrap();
                    let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                    if root_fpvar.value().is_ok() {
                        println!("final root in prover {:?}", self.final_root);
                    }
                    let addr = FinalRootAddress {}.to_string();
                    let _ = pm.set(addr, &root_fpvar).unwrap();
                    let root_var =
                        UInt8::new_witness_vec(cs.clone(), &self.params.null_leaf).unwrap();
                    let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
                    let addr = NullLeafAddress {}.to_string();
                    let _ = pm.set(addr, &root_fpvar).unwrap();
                },
                PrimitiveSubcircuit::PaddingPrimitive(_) => {},
            }
        }

        let ending_num_constraints = cs.num_constraints();
        println!(
            "Test subcircuit {subcircuit_idx} costs {} constraints",
            ending_num_constraints - starting_num_constraints
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::portal_manager::SetupRomPortalManager;
    use crate::transcript::TranscriptEntry;
    use crate::vkd::sparse_tree::{MerkleTreeParameters, SparseMerkleTree};
    use crate::vkd::vkd::{
        VerifiableKeyDirectoryCircuit, VerifiableKeyDirectoryCircuitParams, DEPTH,
    };
    use crate::CircuitWithPortals;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use std::time::Instant;

    #[test]
    fn test_vkd_subcircuit() {
        #[derive(Clone, Debug)]
        pub struct MerkleTreeTestParameters;
        impl MerkleTreeParameters for MerkleTreeTestParameters {
            const DEPTH: usize = DEPTH;
        }

        type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;
        let tree = TestMerkleTree::new().unwrap();

        let vkd_params = VerifiableKeyDirectoryCircuitParams {
            log_num_subcircuits: 4,
            null_leaf: tree.sparse_initial_hashes[DEPTH],
        };
        let mut vkd: VerifiableKeyDirectoryCircuit =
            VerifiableKeyDirectoryCircuit::new(&vkd_params);

        // testing the lazy static making sure the vkd is initiated only once for each params
        let now = Instant::now();
        for _i in 0..1000000 {
            vkd = VerifiableKeyDirectoryCircuit::new(&vkd_params);
        }
        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);

        println!(
            "vkd.num_subcircuits(): {}, vkd.subcircuits.len(): {}",
            vkd.num_subcircuits(),
            vkd.subcircuits.len()
        );

        // initializing the portal manager
        let expected_subtraces = vkd.get_portal_subtraces();
        let mut pm: SetupRomPortalManager<Fr> =
            SetupRomPortalManager::new(ConstraintSystem::new_ref());
        let cs = pm.cs.clone();
        for subcircuit_idx in 0..vkd.subcircuits.len() {
            pm.start_subtrace(cs.clone());
            let subcircuit_bytes = vkd.get_serialized_witnesses(subcircuit_idx);
            vkd.set_serialized_witnesses(subcircuit_idx, subcircuit_bytes.as_slice());
            vkd.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                .unwrap();
            println!(
                "update: {:?}, index:{subcircuit_idx}, type:{}, representative: {}",
                vkd.subcircuits[subcircuit_idx].get_update_idx(),
                vkd.subcircuits[subcircuit_idx].get_type(),
                vkd.representative_subcircuit(subcircuit_idx),
            );
        }

        assert!(pm.cs.is_satisfied().unwrap());

        let wrapped_subtraces = pm
            .subtraces
            .into_iter()
            .map(|st| {
                st.into_iter()
                    .map(|e| TranscriptEntry::Rom(e))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        //assert_eq!(wrapped_subtraces, expected_subtraces);
        for (i, (actual, expected)) in wrapped_subtraces
            .iter()
            .zip(expected_subtraces.iter())
            .enumerate()
        {
            assert_eq!(
                actual.len(),
                expected.len(),
                "Length mismatch at subtrace {}",
                i
            );
            for (j, (actual, expected)) in actual.iter().zip(expected.iter()).enumerate() {
                assert_eq!(actual, expected, "Mismatch at subtrace {}, entry {}", i, j);
            }
        }
    }
}
