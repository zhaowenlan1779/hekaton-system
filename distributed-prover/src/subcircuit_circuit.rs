use crate::{
    eval_tree::{
        ExecTreeLeaf, ExecTreeLeafVar, ExecTreeParams, LeafParamVar, MerkleRoot, MerkleRootVar,
        SerializedLeafVar, TwoToOneParamVar,
    },
    portal_manager::{PortalManager, ProverPortalManager},
    transcript::{MemType, TranscriptEntry, TranscriptEntryVar},
    util::log2,
    CircuitWithPortals,
};

use std::marker::PhantomData;

use ark_cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};
use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget as TreeConfigGadget, PathVar as MerklePathVar},
    Config as TreeConfig, Path as MerklePath,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    ToConstraintFieldGadget,
};
use ark_relations::{ns, r1cs::SynthesisError};

// A ZK circuit that takes a CircuitWithPortals and proves just 1 subcircuit
pub struct SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    pub subcircuit_idx: usize,
    pub circ: Option<P>,

    // Merkle tree things
    pub tree_params: ExecTreeParams<C>,

    // Stage 0 committed values
    pub time_ordered_subtrace: Vec<TranscriptEntry<F>>,
    pub addr_ordered_subtrace: Vec<TranscriptEntry<F>>,
    pub(crate) time_ordered_subtrace_var: Vec<TranscriptEntryVar<F>>,
    pub(crate) addr_ordered_subtrace_var: Vec<TranscriptEntryVar<F>>,

    // Stage 1 witnesses
    pub(crate) cur_leaf: ExecTreeLeaf<F>,
    pub next_leaf_membership: MerklePath<C>,

    // Stage 1 public inputs
    pub challenges: Vec<F>,
    pub root: MerkleRoot<C>,

    pub _marker: PhantomData<CG>,
}

impl<F, P, C, CG> Clone for SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F> + Clone,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    fn clone(&self) -> Self {
        SubcircuitWithPortalsProver {
            subcircuit_idx: self.subcircuit_idx,
            circ: self.circ.clone(),
            tree_params: self.tree_params.clone(),
            time_ordered_subtrace: self.time_ordered_subtrace.clone(),
            addr_ordered_subtrace: self.addr_ordered_subtrace.clone(),
            time_ordered_subtrace_var: self.time_ordered_subtrace_var.clone(),
            addr_ordered_subtrace_var: self.addr_ordered_subtrace_var.clone(),
            cur_leaf: self.cur_leaf.clone(),
            next_leaf_membership: self.next_leaf_membership.clone(),
            challenges: self.challenges.clone(),
            root: self.root.clone(),
            _marker: self._marker.clone(),
        }
    }
}

impl<F, P, C, CG> SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    // Makes a new struct with subcircuit idx 0, no subtraces, and an empty Merkle auth path
    pub fn new(tree_params: ExecTreeParams<C>, num_subcircuits: usize) -> Self {
        // Create an auth path of the correct length
        let auth_path_len = log2(num_subcircuits) - 1;
        let mut auth_path = MerklePath::default();
        auth_path.auth_path = vec![C::InnerDigest::default(); auth_path_len];

        let challenges_len = match P::MEM_TYPE {
            MemType::Rom => 2,
            MemType::Ram => 4,
        };

        SubcircuitWithPortalsProver {
            subcircuit_idx: 0,
            circ: None,
            tree_params,
            time_ordered_subtrace: Vec::new(),
            addr_ordered_subtrace: Vec::new(),
            time_ordered_subtrace_var: Vec::new(),
            addr_ordered_subtrace_var: Vec::new(),
            cur_leaf: ExecTreeLeaf::padding(P::MEM_TYPE),
            next_leaf_membership: auth_path,
            challenges: vec![F::zero(); challenges_len],
            root: MerkleRoot::<C>::default(),
            _marker: PhantomData,
        }
    }
}

impl<F, P, C, CG> MultiStageConstraintSynthesizer<F> for SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F, Leaf = SerializedLeafVar<F>>,
{
    /// Two stages: Subtrace commit, and the rest
    fn total_num_stages(&self) -> usize {
        2
    }

    /// Generates constraints for the i-th stage.
    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        // At stage 0, witness both subtraces and exit
        if stage == 0 {
            return cs.synthesize_with(|c| {
                self.time_ordered_subtrace_var = self
                    .time_ordered_subtrace
                    .iter()
                    .map(|entry| TranscriptEntryVar::new_witness(ns!(c, "time"), || Ok(entry)))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                self.addr_ordered_subtrace_var = self
                    .addr_ordered_subtrace
                    .iter()
                    .map(|entry| TranscriptEntryVar::new_witness(ns!(c, "addr"), || Ok(entry)))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                println!(
                    "Witnessed trace of size {}",
                    self.time_ordered_subtrace.len()
                );
                Ok(())
            });
        }
        if stage > 1 {
            panic!("there are only two stages in the subcircuit prover");
        }

        // Everything below is stage 1
        cs.synthesize_with(|c| {
            // Witness all the necessary variables
            // This does NOT witness the RunningEvals challenges. That must be done separately
            let cur_leaf_var = ExecTreeLeafVar::new_witness(ns!(c, "leaf"), || Ok(&self.cur_leaf))?;
            let next_leaf_membership_var =
                MerklePathVar::<_, _, CG>::new_witness(ns!(c, "path"), || {
                    Ok(&self.next_leaf_membership)
                })?;
            let challenge_vars = self
                .challenges
                .iter()
                .map(|chal| FpVar::new_input(ns!(c, "chal"), || Ok(chal)))
                .collect::<Result<Vec<_>, _>>()?;
            let root_var = MerkleRootVar::<_, _, CG>::new_input(ns!(c, "root"), || Ok(&self.root))?;

            // Input the Merkle tree params as constants
            let leaf_params_var = LeafParamVar::<CG, _, _>::new_constant(
                ns!(c, "leaf param"),
                &self.tree_params.leaf_params,
            )?;
            let two_to_one_params_var = TwoToOneParamVar::<CG, _, _>::new_constant(
                ns!(c, "2-to-1 param"),
                &self.tree_params.two_to_one_params,
            )?;

            // Ensure that at subcircuit 0, the provided evals and last subtrace entry are the
            // defaults
            if self.subcircuit_idx == 0 {
                // Check the evals are (1, 1)
                cur_leaf_var
                    .evals
                    .time_ordered_eval()
                    .enforce_equal(&FpVar::one())?;
                cur_leaf_var
                    .evals
                    .addr_ordered_eval()
                    .enforce_equal(&FpVar::one())?;

                // Check the subtrace entry prior to the beginning is a padding entry
                cur_leaf_var
                    .last_subtrace_entry
                    .is_padding()?
                    .enforce_equal(&Boolean::TRUE)?;
            }

            // Set the challenge values so the running evals knows how to update itself
            let mut running_evals_var = cur_leaf_var.evals.clone();
            running_evals_var.set_challenges(&challenge_vars);

            // Prepend the last subtrace entry to the addr-ordered subtrace. This necessary for the
            // consistency check.
            let full_addr_ordered_subtrace = core::iter::once(&cur_leaf_var.last_subtrace_entry)
                .chain(self.addr_ordered_subtrace_var.iter())
                .cloned()
                .collect::<Vec<_>>();
            // Save the last subtrace entry for a check later
            let last_subtrace_entry = full_addr_ordered_subtrace.last().unwrap().clone();

            // Create the portal manager to give to the circuit
            let mut pm = P::ProverPortalManager::new(
                self.time_ordered_subtrace_var.clone(),
                full_addr_ordered_subtrace,
                running_evals_var,
            );

            // Run the specific subcircuit and give it the prepared portal manager
            self.circ
                .as_mut()
                .expect("must provide circuit for stage 1 computation")
                .generate_constraints(c.clone(), self.subcircuit_idx, &mut pm)?;

            // Sanity checks: make sure all the subtraces were used. The addr-ordered one has 1
            // remaining because it starts with 1 extra. The last one is used, but it's not popped.
            // TODO: Add sanity check back eventually. Probably good for debugging if we need it
            //assert_eq!(pm.next_entry_idx, pm.time_ordered_subtrace.len());

            // Make sure the resulting tree leaf appears in the Merkle Tree
            let next_leaf = ExecTreeLeafVar {
                evals: pm.running_evals().clone(),
                last_subtrace_entry,
            };

            next_leaf_membership_var
                .verify_membership(
                    &leaf_params_var,
                    &two_to_one_params_var,
                    &root_var,
                    &next_leaf.to_constraint_field()?,
                )?
                .enforce_equal(&Boolean::TRUE)?;

            // If this is the last subcircuit, then verify that the time- and addr-ordered evals
            // are equal. This completes the permutation check.
            if self.subcircuit_idx == self.circ.as_ref().unwrap().num_subcircuits() - 1 {
                next_leaf
                    .evals
                    .time_ordered_eval()
                    .enforce_equal(&next_leaf.evals.addr_ordered_eval())?;
            }

            println!(
                "Full subcircuit {} costs {} constraints",
                self.subcircuit_idx,
                c.num_constraints()
            );

            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;
    use std::{collections::HashMap, rc::Rc};

    use super::*;

    use crate::{
        aggregation::AggProvingKey,
        coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage1Request},
        poseidon_util::{
            gen_merkle_params, PoseidonTreeConfig as TestParams,
            PoseidonTreeConfigVar as TestParamsVar,
        },
        tree_hash_circuit::*,
        util::{G16Com, G16ComSeed, G16ProvingKey},
        vkd::{VerifiableKeyDirectoryCircuit, VerifiableKeyDirectoryCircuitParams},
        vm::VirtualMachine,
        worker::{process_stage0_request, process_stage1_request, Stage0Response},
    };
    use sha2::Sha256;

    use crate::vkd::{MerkleTreeConcreteParameters, SparseMerkleTree, DEPTH};
    use crate::vm::VirtualMachineParameters;
    use ark_bn254::{Bn254 as E, Fr};
    use ark_cp_groth16::verifier::prepare_verifying_key;
    use ark_ff::UniformRand;
    use ark_ip_proofs::tipa::TIPA;
    use ark_std::test_rng;

    // Checks that the SubcircuitWithPortalsProver is satisfied when the correct inputs are given
    #[test]
    fn test_subcircuit_portal_prover_satisfied() {
        let mut rng = test_rng();
        let tree_params = gen_merkle_params();

        // Make a random Merkle tree
        let circ_params = MerkleTreeCircuitParams {
            num_leaves: 4,
            num_sha_iters_per_subcircuit: 4,
            num_portals_per_subcircuit: 12,
        };
        let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &circ_params);
        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

        // Make the stage0 coordinator state. The value of the commitment key doesn't really matter
        // since we don't test aggregation here.
        let (tipp_pk, _tipp_vk) = TIPA::<_, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
        let stage0_state = CoordinatorStage0State::new::<TestParams>(circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        // Worker receives a stage0 package containing all the subtraces it will need for this run.
        // In this test, it's simply all of them. We imagine that the worker stores its copy of
        // this for later use in stage 1
        let stage0_reqs = all_subcircuit_indices
            .iter()
            .map(|idx| stage0_state.gen_request(*idx).to_owned())
            .collect::<Vec<_>>();

        // Make fake stage0 responses that cover all the subcircuits and has random commitments
        let fake_stage0_resps = all_subcircuit_indices
            .iter()
            .map(|idx| Stage0Response::<E> {
                subcircuit_idx: *idx,
                com: G16Com::<E>::rand(&mut rng),
                com_seed: G16ComSeed::default(),
            })
            .collect::<Vec<_>>();

        // Move on to stage 1. Make the coordinator state
        let stage1_state = stage0_state.process_stage0_responses(
            &tipp_pk,
            tree_params.clone(),
            &fake_stage0_resps,
        );

        // Compute the values needed to prove stage1 for all subcircuits
        let stage1_reqs = all_subcircuit_indices
            .iter()
            .map(|idx| stage1_state.gen_request(*idx))
            .collect::<Vec<_>>();

        // Now for every subcircuit, instantiate a subcircuit prover and check that its constraints
        // are satisfied
        for (stage0_req, stage1_req) in stage0_reqs.into_iter().zip(stage1_reqs.into_iter()) {
            assert_eq!(stage0_req.subcircuit_idx, stage1_req.subcircuit_idx);
            let subcircuit_idx = stage0_req.subcircuit_idx;

            let challenges = stage1_req.cur_leaf.evals.challenges();

            // Make an empty version of the large circuit and fill in just the witnesses for the
            // subcircuit we're proving now
            let mut partial_circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
            <MerkleTreeCircuit as CircuitWithPortals<Fr>>::set_serialized_witnesses(
                &mut partial_circ,
                subcircuit_idx,
                &stage1_req.serialized_witnesses,
            );

            let mut subcirc_circ = SubcircuitWithPortalsProver {
                subcircuit_idx,
                circ: Some(partial_circ),
                tree_params: tree_params.clone(),
                time_ordered_subtrace: stage0_req.time_ordered_subtrace.clone(),
                addr_ordered_subtrace: stage0_req.addr_ordered_subtrace.clone(),
                time_ordered_subtrace_var: Vec::new(),
                addr_ordered_subtrace_var: Vec::new(),
                cur_leaf: stage1_req.cur_leaf,
                next_leaf_membership: stage1_req.next_leaf_membership,
                challenges,
                root: stage1_req.root,
                _marker: PhantomData::<TestParamsVar>,
            };

            // Run both stages
            let mut mcs = MultiStageConstraintSystem::default();
            subcirc_circ.generate_constraints(0, &mut mcs).unwrap();
            subcirc_circ.generate_constraints(1, &mut mcs).unwrap();

            // Check that everything worked
            assert!(mcs.is_satisfied().unwrap());
        }
    }

    // Runs a full proof of the MerkleTreeCircuit
    #[test]
    fn test_merkle_e2e_prover() {
        let circ_params = MerkleTreeCircuitParams {
            num_leaves: 2,
            num_sha_iters_per_subcircuit: 1,
            num_portals_per_subcircuit: 1,
        };
        run_e2e_prover::<MerkleTreeCircuit>(circ_params);
    }

    // Runs a full proof of the VKD circuit
    #[test]
    fn test_vkd_e2e_prover() {
        type TestMerkleTree = SparseMerkleTree<MerkleTreeConcreteParameters>;
        let tree = TestMerkleTree::new().unwrap();

        let circ_params = VerifiableKeyDirectoryCircuitParams {
            // 5 <= log_num_subcircuits <= 50
            log_num_subcircuits: 10,
            null_leaf: tree.sparse_initial_hashes[DEPTH],
        };
        run_e2e_prover::<VerifiableKeyDirectoryCircuit>(circ_params);
    }

    // Runs a full proof of the VM circuit
    #[test]
    fn test_vm_e2e_prover() {
        let virtual_machine_parameter = VirtualMachineParameters {
            use_merkle_memory: false,
            log_num_subcircuit: 3,
            dummy_constraint_num: 30,
            operations_per_chunk: 2,
        };
        run_e2e_prover::<VirtualMachine<Fr>>(virtual_machine_parameter);
    }

    // Runs a full prover for the given CircuitWithPortals type and parameters
    fn run_e2e_prover<P>(circ_params: P::Parameters)
    where
        P: CircuitWithPortals<Fr> + Clone,
    {
        let start_a = Instant::now();
        let mut rng = test_rng();
        let tree_params = gen_merkle_params();

        let circ = P::rand(&mut rng, &circ_params);
        let num_subcircuits = P::num_subcircuits(&circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        // Coordinator generates all the proving keys. We only need to generate the proving keys for the minimal set of unique subcircuits
        let minimal_proving_keys: HashMap<usize, Rc<G16ProvingKey<E>>> = {
            let generator = G16ProvingKeyGenerator::<TestParams, TestParamsVar, _, _>::new(
                circ.clone(),
                tree_params.clone(),
            );
            let minimal_subcircuit_indices = P::get_unique_subcircuits(&circ);
            minimal_subcircuit_indices
                .iter()
                .map(|&i| (i, Rc::new(generator.gen_pk(&mut rng, i))))
                .collect()
        };
        // Now make the full set of proving keys
        let proving_keys: Vec<Rc<G16ProvingKey<E>>> = all_subcircuit_indices
            .iter()
            .map(|&i| {
                let representative_idx = P::representative_subcircuit(&circ, i);
                minimal_proving_keys
                    .get(&representative_idx)
                    .unwrap()
                    .clone()
            })
            .collect();

        let duration_a = start_a.elapsed();
        println!("Part A took: {:?}", duration_a);

        let start_b = Instant::now();

        // Make the stage0 coordinator state
        let stage0_state = CoordinatorStage0State::new::<TestParams>(circ);

        // Workers receives stage0 packages containing the subtraces it will need for this run. We
        // imagine the worker saves their package to disk.
        let stage0_reqs = all_subcircuit_indices
            .iter()
            .map(|&idx| stage0_state.gen_request(idx).to_owned())
            .collect::<Vec<_>>();

        // Make stage0 responses wrt the real proving keys. This contains all the commitments
        let stage0_resps = stage0_reqs
            .iter()
            .zip(proving_keys.iter())
            .map(|(req, pk)| {
                process_stage0_request::<_, TestParamsVar, _, P, _>(
                    &mut rng,
                    tree_params.clone(),
                    &pk,
                    req.clone(),
                )
            })
            .collect::<Vec<_>>();

        let duration_b = start_b.elapsed();
        println!("Part B took: {:?}", duration_b);

        let start_c = Instant::now();

        // Move on to stage 1. Make the coordinator state
        let (tipp_pk, _tipp_vk) = TIPA::<E, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
        let stage1_state =
            stage0_state.process_stage0_responses(&tipp_pk, tree_params.clone(), &stage0_resps);

        // Compute the values needed to prove stage1 for all subcircuits
        let stage1_reqs: Vec<Stage1Request<TestParams, _, _>> = all_subcircuit_indices
            .iter()
            .map(|idx| stage1_state.gen_request(*idx).to_owned())
            .collect();

        let duration_c = start_c.elapsed();
        println!("Part C took: {:?}", duration_c);

        let start_d = Instant::now();
        // Convert the coordinator state into a final aggregator state. We can throw away most of
        // our circuit data now
        let final_agg_state = stage1_state.into_agg_state();

        // Now compute all the proofs, check them, and collect them for aggregation
        let stage1_resps = stage0_reqs
            .into_iter()
            .zip(stage0_resps.into_iter())
            .zip(stage1_reqs.into_iter())
            .zip(proving_keys.iter())
            .map(|(((stage0_req, stage0_resp), stage1_req), pk)| {
                // Compute the proof
                let resp = process_stage1_request::<_, TestParamsVar, _, _, _>(
                    &mut rng,
                    tree_params.clone(),
                    &pk,
                    stage0_req,
                    &stage0_resp,
                    stage1_req,
                );

                // Verify

                let _public_inputs = &final_agg_state.public_inputs;
                let _pvk = prepare_verifying_key(&pk.vk());
                // assert!(verify_proof(&pvk, &resp.proof, &public_inputs).unwrap());

                resp
            })
            .collect::<Vec<_>>();

        let duration_d = start_d.elapsed();
        println!("Part D took: {:?}", duration_d);

        let start_e = Instant::now();

        // Do aggregation. Make up whatever keys are necessary
        let agg_ck = AggProvingKey::new(tipp_pk, |i| &proving_keys[i]);

        // Compute the aggregate proof
        final_agg_state.gen_agg_proof(&agg_ck, &stage1_resps);

        let duration_e = start_e.elapsed();
        println!("Part E took: {:?}", duration_e);

        // TODO: Check verification
    }
}
