use crate::data_structures::{
    G16Com, G16ComRandomness, ProvingKeys, Stage0RequestRef, Stage0Response, Stage1RequestRef,
    Stage1Response,
};

use distributed_prover::{
    eval_tree::ExecTreeParams,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    subcircuit_circuit::SubcircuitWithPortalsProver,
    util::QAP,
    worker::{process_stage0_request_get_cb, process_stage1_request_with_cb},
    CircuitWithPortals,
};

use ark_bn254::{Bn254 as E, Fr};
use ark_cp_groth16::committer::CommitmentBuilder as G16CommitmentBuilder;
use ark_ff::UniformRand;
use rand::{Rng, SeedableRng};

type CommitterState<'a, P> =
    G16CommitmentBuilder<'a, SubcircuitWithPortalsProver<Fr, P, TreeConfig, TreeConfigVar>, E, QAP>;

pub struct WorkerState<'a, P: CircuitWithPortals<Fr>> {
    g16_pks: &'a ProvingKeys,
    tree_params: ExecTreeParams<TreeConfig>,
    cb: Option<CommitterState<'a, P>>,
    com: G16Com,
    com_rand: G16ComRandomness,
    #[allow(unused)]
    num_subcircuits: usize,
}

impl<'a, P: CircuitWithPortals<Fr>> WorkerState<'a, P> {
    pub fn new(num_subcircuits: usize, g16_pks: &'a ProvingKeys) -> Self {
        let tree_params = gen_merkle_params();
        WorkerState {
            g16_pks,
            tree_params,
            cb: None,
            com: G16Com::default(),
            com_rand: G16ComRandomness::default(),
            num_subcircuits,
        }
    }

    pub fn stage_0(&mut self, mut rng: impl Rng, stage0_req: &Stage0RequestRef) -> Stage0Response {
        let subcircuit_idx = stage0_req.subcircuit_idx;
        let g16_pk = self.g16_pks.get_pk(subcircuit_idx);

        // Process the request. This returns the response and the commitment builder. Save the
        // builder as state
        let (resp, cb) = process_stage0_request_get_cb::<_, TreeConfigVar, _, P, _>(
            &mut rng,
            self.tree_params.clone(),
            g16_pk,
            stage0_req.to_owned(),
        );

        // Recover the com and com randomness
        let com = resp.com;
        let com_rand = {
            let mut subcircuit_rng = rand_chacha::ChaCha12Rng::from_seed(resp.com_seed);
            Fr::rand(&mut subcircuit_rng)
        };

        // Now set the local values
        self.cb = Some(cb);
        self.com = com;
        self.com_rand = com_rand;

        resp
    }

    pub fn stage_1(self, mut rng: impl Rng, stage1_req: &Stage1RequestRef<P>) -> Stage1Response {
        // Use the builder to respond
        process_stage1_request_with_cb(
            &mut rng,
            self.cb.unwrap(),
            self.com,
            self.com_rand,
            stage1_req.to_owned(),
        )
    }
}

/// Safety: This is only safe because:
/// * In `node.rs`, `WorkerState` is only ever accessed by one thread at a time
/// * `WorkerState` is only `!Send` because it contains a `CommitterState`, and
///  `CommitterState` is `!Send` because it contains `ConstraintSystemRef`s.
///  However, no other thread has access to the `WorkerState` of another thread,
///  and so we don't have any mutable access issues.
unsafe impl<'a, P: CircuitWithPortals<Fr>> Send for WorkerState<'a, P> {}

/// Safety: This is only safe because:
/// * In `node.rs`, `WorkerState` is only ever accessed by one thread at a time
/// * `WorkerState` is only `!Send` because it contains a `CommitterState`, and
///  `CommitterState` is `!Send` because it contains `ConstraintSystemRef`s.
///  However, no other thread has access to the `WorkerState` of another thread,
///  and so we don't have any mutable access issues.
unsafe impl<'a, P: CircuitWithPortals<Fr>> Sync for WorkerState<'a, P> {}
