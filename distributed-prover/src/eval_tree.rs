use std::borrow::Borrow;

use ark_crypto_primitives::crh::constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{uint8::UInt8, ToBytesGadget},
    fields::fp::FpVar,
    R1CSVar, ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) type MerkleRoot<C> = <C as TreeConfig>::InnerDigest;
pub(crate) type MerkleRootVar<C, F, CG> = <CG as TreeConfigGadget<C, F>>::InnerDigest;

use crate::transcript::{
    MemType, RunningEvaluation, RunningEvaluationVar, TranscriptEntry, TranscriptEntryVar,
};
pub use ark_crypto_primitives::merkle_tree::{
    constraints::ConfigGadget as TreeConfigGadget, Config as TreeConfig, LeafParam, TwoToOneParam,
};

pub(crate) type LeafParamVar<CG, C, F> = <<CG as TreeConfigGadget<C, F>>::LeafHash as CRHSchemeGadget<
    <C as TreeConfig>::LeafHash,
    F,
>>::ParametersVar;
pub(crate) type TwoToOneParamVar<CG, C, F> =
    <<CG as TreeConfigGadget<C, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <C as TreeConfig>::TwoToOneHash,
        F,
    >>::ParametersVar;

pub struct ExecTreeParams<C: TreeConfig> {
    pub leaf_params: LeafParam<C>,
    pub two_to_one_params: TwoToOneParam<C>,
}

impl<C: TreeConfig> Clone for ExecTreeParams<C> {
    fn clone(&self) -> Self {
        ExecTreeParams {
            leaf_params: self.leaf_params.clone(),
            two_to_one_params: self.two_to_one_params.clone(),
        }
    }
}

/// A leaf in the execution tree
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct ExecTreeLeaf<F: PrimeField> {
    // Leaf i contains the running evals AFTER having run subcircuit i
    pub evals: RunningEvaluation<F>,
    // Leaf i contains the last entry of the i-th addr-ordered subtrace
    pub last_subtrace_entry: TranscriptEntry<F>,
}

// The default value doesn't matter much, as it will always be overridden
impl<F: PrimeField> Default for ExecTreeLeaf<F> {
    fn default() -> Self {
        ExecTreeLeaf {
            evals: RunningEvaluation::default(MemType::Rom),
            last_subtrace_entry: TranscriptEntry::padding(MemType::Rom),
        }
    }
}

impl<F: PrimeField> ExecTreeLeaf<F> {
    /// We need to give a starting set of values to the first subcircuit. This is the padding leaf.
    /// It has empty running evals and an all-zero transcript entry
    pub(crate) fn padding(mem_type: MemType) -> Self {
        ExecTreeLeaf {
            evals: RunningEvaluation::default(mem_type),
            last_subtrace_entry: TranscriptEntry::padding(mem_type),
        }
    }
}

impl<F: PrimeField> ToConstraintField<F> for ExecTreeLeaf<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(
            [
                vec![self.evals.time_ordered_eval()],
                vec![self.evals.addr_ordered_eval()],
                self.last_subtrace_entry
                    .to_field_elements()
                    .unwrap_or(Vec::new()),
            ]
            .concat(),
        )
    }
}

/// The ZK version of `Leaf`
pub(crate) struct ExecTreeLeafVar<F: PrimeField> {
    pub evals: RunningEvaluationVar<F>,
    pub last_subtrace_entry: TranscriptEntryVar<F>,
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for ExecTreeLeafVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        Ok([
            vec![self.evals.time_ordered_eval().clone()],
            vec![self.evals.addr_ordered_eval().clone()],
            self.last_subtrace_entry.to_constraint_field()?,
        ]
        .concat())
    }
}

/// `ExecTreeLeaf` serializes to bytes. This is the form it's in when put into the exec tree
pub(crate) type SerializedLeaf<F> = [F];

/// The ZK version of `SerializedLeaf`
pub(crate) type SerializedLeafVar<F> = [FpVar<F>];

impl<F: PrimeField> R1CSVar<F> for ExecTreeLeafVar<F> {
    type Value = ExecTreeLeaf<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.evals.cs().or(self.last_subtrace_entry.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(ExecTreeLeaf {
            evals: self.evals.value()?,
            last_subtrace_entry: self.last_subtrace_entry.value()?,
        })
    }
}

// Serialization here is compatible with with ExecTreeLeaf::to_bytes()
impl<F: PrimeField> ToBytesGadget<F> for ExecTreeLeafVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([self.evals.to_bytes()?, self.last_subtrace_entry.to_bytes()?].concat())
    }
}

impl<F: PrimeField> AllocVar<ExecTreeLeaf<F>, F> for ExecTreeLeafVar<F> {
    fn new_variable<T: Borrow<ExecTreeLeaf<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let leaf = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let evals =
            RunningEvaluationVar::new_variable(ns!(cs, "evals"), || leaf.map(|l| &l.evals), mode)?;
        let last_subtrace_entry = TranscriptEntryVar::new_variable(
            ns!(cs, "last entry"),
            || leaf.map(|l| &l.last_subtrace_entry),
            mode,
        )?;

        Ok(ExecTreeLeafVar {
            evals,
            last_subtrace_entry,
        })
    }
}
