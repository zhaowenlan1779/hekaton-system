use crate::data_structures::{
    AggProof, ProvingKeys, Stage0RequestRef, Stage0Response, Stage1RequestRef, Stage1Response,
};

use distributed_prover::{
    aggregation::AggProvingKey,
    coordinator::{CoordinatorStage0State, CoordinatorStage1State},
    poseidon_util::{gen_merkle_params, PoseidonTreeConfig as TreeConfig},
    CircuitWithPortals,
};

use ark_bn254::{Bn254 as E, Fr};
use ark_ip_proofs::tipa::TIPA;
use ark_serialize::CanonicalDeserialize;
use ark_std::{end_timer, start_timer};
use rand::thread_rng;

pub struct CoordinatorState<'a, P: CircuitWithPortals<Fr>> {
    g16_pks: &'a ProvingKeys,
    agg_pk: AggProvingKey<'a, E>,
    circ_params: P::Parameters,
    stage0_state: Option<CoordinatorStage0State<E, P>>,
    stage1_state: Option<CoordinatorStage1State<TreeConfig, E, P>>,
}

impl<'a, P: CircuitWithPortals<Fr>> CoordinatorState<'a, P> {
    pub fn new(g16_pks: &'a ProvingKeys) -> CoordinatorState<'a, P> {
        let circ_params = P::Parameters::deserialize_uncompressed_unchecked(
            g16_pks.serialized_circ_params.as_slice(),
        )
        .unwrap();

        CoordinatorState {
            circ_params,
            agg_pk: generate_agg_key(&g16_pks),
            g16_pks,
            stage0_state: None,
            stage1_state: None,
        }
    }

    pub fn get_pks(&self) -> &ProvingKeys {
        &self.g16_pks
    }

    pub fn stage_0(&mut self) -> Vec<Stage0RequestRef> {
        let mut rng = thread_rng();

        let circ = P::rand(&mut rng, &self.circ_params);
        let num_subcircuits = self.g16_pks.num_subcircuits();

        self.stage0_state = Some(CoordinatorStage0State::new::<TreeConfig>(circ));
        (0..num_subcircuits)
            .map(|idx| self.stage0_state.as_ref().unwrap().gen_request(idx))
            .collect::<Vec<_>>()
    }

    pub fn stage_1(&mut self, stage0_resps: &[Stage0Response]) -> Vec<Stage1RequestRef<P>> {
        let tree_params = gen_merkle_params();
        let num_subcircuits = self.g16_pks.num_subcircuits();

        // Consume the stage0 state and the responses
        self.stage1_state = Some(self.stage0_state.take().unwrap().process_stage0_responses(
            &self.agg_pk.tipp_pk,
            tree_params,
            &stage0_resps,
        ));

        (0..num_subcircuits)
            .map(|idx| self.stage1_state.as_ref().unwrap().gen_request(idx))
            .collect::<Vec<_>>()
    }

    pub fn aggregate(&mut self, stage1_resps: &[Stage1Response]) -> AggProof {
        let final_agg_state = self.stage1_state.take().unwrap().into_agg_state();
        final_agg_state.gen_agg_proof(&self.agg_pk, stage1_resps)
    }
}

fn generate_agg_key(g16_pks: &ProvingKeys) -> AggProvingKey<E> {
    let mut rng = thread_rng();

    let num_subcircuits = g16_pks.num_subcircuits();

    let pk_fetcher = |subcircuit_idx: usize| g16_pks.get_pk(subcircuit_idx);

    // Construct the aggregator commitment key
    let start = start_timer!(|| format!("Generating aggregation key "));
    let agg_pk = {
        // Need some intermediate keys
        let (tipp_pk, _tipp_vk) =
            TIPA::<E, sha2::Sha256>::setup(num_subcircuits, &mut rng).unwrap();
        AggProvingKey::new(tipp_pk, pk_fetcher)
    };
    end_timer!(start);
    agg_pk
}
