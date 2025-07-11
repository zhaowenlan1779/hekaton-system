use distributed_prover::{
    coordinator::G16ProvingKeyGenerator,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    CircuitWithPortals,
};

use ark_bn254::{Bn254 as E, Fr};
use ark_ip_proofs::tipa::Proof;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Write,
};
use rand::SeedableRng;
use std::collections::BTreeMap;

pub type G16Proof = distributed_prover::util::G16Proof<E>;
pub type G16ProvingKey = distributed_prover::util::G16ProvingKey<E>;
pub type G16Com = distributed_prover::util::G16Com<E>;
pub type G16ComRandomness = distributed_prover::util::G16ComRandomness<E>;
pub type AggProof = Proof<E>;

pub type Stage0Request = distributed_prover::coordinator::Stage0Request<Fr>;

pub type Stage0RequestRef<'a> = distributed_prover::coordinator::Stage0RequestRef<'a, Fr>;

pub type Stage1Request<P> = distributed_prover::coordinator::Stage1Request<TreeConfig, Fr, P>;

pub type Stage1RequestRef<'a, P> =
    distributed_prover::coordinator::Stage1RequestRef<'a, TreeConfig, Fr, P>;

pub type Stage0Response = distributed_prover::worker::Stage0Response<E>;

pub type Stage1Response = distributed_prover::worker::Stage1Response<E>;

pub const MERKLE_CIRCUIT_ID: &'static str = "BigMerkle circuit";
pub const VKD_CIRCUIT_ID: &'static str = "VKD circuit";
pub const VM_CIRCUIT_ID: &'static str = "VM circuit";
pub const R1CS_CIRCUIT_ID: &'static str = "R1CS circuit";

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKeys {
    circuit_id: String,
    /// The parameters to the underlying circuit, serialized
    pub serialized_circ_params: Vec<u8>,
    /// The proving keys for a minimal set of subcircuits
    minimal_proving_keys: BTreeMap<usize, G16ProvingKey>,
    /// The map from subcircuit idx to its canonical representative in `minimal_proving_keys`
    subcircuit_representative_map: BTreeMap<usize, usize>,
}

impl ProvingKeys {
    pub fn new<P: CircuitWithPortals<Fr>>(circ_params: P::Parameters, id_str: String) -> Self {
        let seed = [69u8; 32];
        let mut rng = rand::rngs::StdRng::from_seed(seed);

        let circ = P::rand(&mut rng, &circ_params);
        let tree_params = gen_merkle_params();

        let pk_generator = G16ProvingKeyGenerator::<TreeConfig, TreeConfigVar, E, _>::new(
            circ.clone(),
            tree_params.clone(),
        );

        // Serialize circuit params
        let mut serialized_circ_params = Vec::new();
        circ_params
            .serialize_uncompressed(&mut serialized_circ_params)
            .unwrap();

        // Generate the relevant proving keys
        let minimal_proving_keys: BTreeMap<usize, G16ProvingKey> = {
            let minimal_subcircuit_indices = circ.get_unique_subcircuits();
            minimal_subcircuit_indices
                .iter()
                .map(|&i| (i, pk_generator.gen_pk(&mut rng, i)))
                .collect()
        };

        // Generate the full index mapping
        let subcircuit_representative_map = (0..circ.num_subcircuits())
            .map(|i| (i, circ.representative_subcircuit(i)))
            .collect();

        ProvingKeys {
            circuit_id: id_str,
            serialized_circ_params,
            minimal_proving_keys,
            subcircuit_representative_map,
        }
    }

    pub fn get_pk(&self, subcircuit_idx: usize) -> &G16ProvingKey {
        let representative_idx = self
            .subcircuit_representative_map
            .get(&subcircuit_idx)
            .expect("subcircuit index out of range");
        self.minimal_proving_keys
            .get(representative_idx)
            .expect("missing proving key")
    }

    pub fn get_id_str(&self) -> &str {
        &self.circuit_id
    }

    pub fn num_subcircuits(&self) -> usize {
        self.subcircuit_representative_map.len()
    }
}

impl<'a> CanonicalSerialize for &'a ProvingKeys {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.serialized_circ_params
            .serialize_with_mode(&mut writer, compress)?;
        self.minimal_proving_keys
            .serialize_with_mode(&mut writer, compress)?;
        self.subcircuit_representative_map
            .serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.serialized_circ_params.serialized_size(compress)
            + self.minimal_proving_keys.serialized_size(compress)
            + self.subcircuit_representative_map.serialized_size(compress)
    }
}
