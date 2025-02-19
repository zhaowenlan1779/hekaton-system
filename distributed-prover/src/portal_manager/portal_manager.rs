use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

use crate::transcript::{RunningEvaluationVar, TranscriptEntryVar};

/// A trait for getting and setting portal wires in partitioned circuits
pub trait PortalManager<F: PrimeField> {
    /// Gets the portal wire of the given name. Panics if no such wire exists.
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError>;

    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError>;

    fn running_evals(&self) -> RunningEvaluationVar<F>;
}

pub trait ProverPortalManager<F: PrimeField>: PortalManager<F> {
    fn new(
        time_ordered_subtrace: Vec<TranscriptEntryVar<F>>,
        addr_ordered_subtrace: Vec<TranscriptEntryVar<F>>,
        running_evals: RunningEvaluationVar<F>,
    ) -> Self;
}
