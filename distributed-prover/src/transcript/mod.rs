mod ram_transcript;

mod rom_transcript;

use std::borrow::Borrow;

use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
pub use ram_transcript::*;
pub use rom_transcript::*;

use crate::aggregation::IppCom;

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum MemType {
    Ram,
    Rom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptEntry<F: PrimeField> {
    Rom(RomTranscriptEntry<F>),
    Ram(RamTranscriptEntry<F>),
}

impl<F: PrimeField> TranscriptEntry<F> {
    pub fn padding(mem_type: MemType) -> Self {
        match mem_type {
            MemType::Ram => TranscriptEntry::Ram(RamTranscriptEntry::padding()),
            MemType::Rom => TranscriptEntry::Rom(RomTranscriptEntry::padding()),
        }
    }

    pub fn addr(&self) -> u64 {
        match self {
            TranscriptEntry::Rom(e) => e.addr,
            TranscriptEntry::Ram(e) => e.addr,
        }
    }

    pub fn timestamp(&self) -> u32 {
        match self {
            TranscriptEntry::Rom(_e) => 0,
            TranscriptEntry::Ram(e) => e.i.representation(),
        }
    }

    pub fn value(&self) -> F {
        match self {
            TranscriptEntry::Rom(e) => e.val,
            TranscriptEntry::Ram(e) => e.val,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunningEvaluation<F: PrimeField> {
    Rom(RomRunningEvaluation<F>),
    Ram(RamRunningEvaluation<F>),
}

impl<F: PrimeField> RunningEvaluation<F> {
    /// Hash the trace commitment to calculate the challenges for the running eval
    pub fn new<E>(mem_type: MemType, com: &IppCom<E>) -> RunningEvaluation<E::ScalarField>
    where
        E: Pairing<ScalarField = F>,
    {
        match mem_type {
            MemType::Ram => RunningEvaluation::Ram(RamRunningEvaluation::<F>::new(com)),
            MemType::Rom => RunningEvaluation::Rom(RomRunningEvaluation::<F>::new(com)),
        }
    }

    pub fn default(mem_type: MemType) -> Self {
        match mem_type {
            MemType::Ram => RunningEvaluation::Ram(RamRunningEvaluation::default()),
            MemType::Rom => RunningEvaluation::Rom(RomRunningEvaluation::default()),
        }
    }

    pub fn update_time_ordered(&mut self, entry: &TranscriptEntry<F>) {
        match self {
            RunningEvaluation::Rom(eval) => match entry {
                TranscriptEntry::Rom(e) => eval.update_time_ordered(e),
                TranscriptEntry::Ram(_) => panic!("Invalid entry type"),
            },
            RunningEvaluation::Ram(eval) => match entry {
                TranscriptEntry::Ram(e) => eval.update_time_ordered(e),
                TranscriptEntry::Rom(_) => panic!("Invalid entry type"),
            },
        }
    }

    pub fn update_addr_ordered(&mut self, entry: &TranscriptEntry<F>) {
        match self {
            RunningEvaluation::Rom(eval) => match entry {
                TranscriptEntry::Rom(e) => eval.update_addr_ordered(e),
                TranscriptEntry::Ram(_) => panic!("Invalid entry type"),
            },
            RunningEvaluation::Ram(eval) => match entry {
                TranscriptEntry::Ram(e) => eval.update_addr_ordered(e),
                TranscriptEntry::Rom(_) => panic!("Invalid entry type"),
            },
        }
    }

    pub fn time_ordered_eval(&self) -> F {
        match self {
            RunningEvaluation::Rom(eval) => eval.time_ordered_eval,
            RunningEvaluation::Ram(eval) => eval.time_ordered_eval,
        }
    }

    pub fn addr_ordered_eval(&self) -> F {
        match self {
            RunningEvaluation::Rom(eval) => eval.addr_ordered_eval,
            RunningEvaluation::Ram(eval) => eval.addr_ordered_eval,
        }
    }

    /// Copies the challenges from the other running eval object
    pub fn copy_challenges_from(&mut self, other: &Self) {
        match self {
            RunningEvaluation::Rom(eval) => match other {
                RunningEvaluation::Rom(other_eval) => eval.challenges = other_eval.challenges,
                RunningEvaluation::Ram(_) => panic!("Invalid entry type"),
            },
            RunningEvaluation::Ram(eval) => match other {
                RunningEvaluation::Ram(other_eval) => eval.challenges = other_eval.challenges,
                RunningEvaluation::Rom(_) => panic!("Invalid entry type"),
            },
        }
    }

    /// Returns the vec of challenges in this running eval object. Panics if they're None
    pub fn challenges(&self) -> Vec<F> {
        match self {
            RunningEvaluation::Rom(eval) => {
                let chals = eval.challenges.unwrap();
                vec![chals.0, chals.1]
            },
            RunningEvaluation::Ram(eval) => {
                let chals = eval.challenges.unwrap();
                vec![chals.0, chals.1, chals.2, chals.3]
            },
        }
    }
}

impl<F: PrimeField> CanonicalSerialize for RunningEvaluation<F> {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            RunningEvaluation::Rom(eval) => {
                writer.write_all(&[0u8])?;
                eval.serialize_with_mode(writer, compress)
            },
            RunningEvaluation::Ram(eval) => {
                writer.write_all(&[1u8])?;
                eval.serialize_with_mode(writer, compress)
            },
        }
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        match self {
            RunningEvaluation::Rom(entry) => 1 + entry.serialized_size(compress),
            RunningEvaluation::Ram(entry) => 1 + entry.serialized_size(compress),
        }
    }
}

impl<F: PrimeField> CanonicalDeserialize for RunningEvaluation<F> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            0u8 => RomRunningEvaluation::deserialize_with_mode(reader, compress, validate)
                .map(RunningEvaluation::Rom),
            1u8 => RamRunningEvaluation::deserialize_with_mode(reader, compress, validate)
                .map(RunningEvaluation::Ram),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl<F: PrimeField> Valid for RunningEvaluation<F> {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            RunningEvaluation::Rom(eval) => eval.check(),
            RunningEvaluation::Ram(eval) => eval.check(),
        }
    }
}

impl<F: PrimeField> CanonicalSerialize for TranscriptEntry<F> {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            TranscriptEntry::Rom(entry) => {
                writer.write_all(&[0u8])?;
                entry.serialize_with_mode(writer, compress)
            },
            TranscriptEntry::Ram(entry) => {
                writer.write_all(&[1u8])?;
                entry.serialize_with_mode(writer, compress)
            },
        }
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        match self {
            TranscriptEntry::Rom(entry) => 1 + entry.serialized_size(compress),
            TranscriptEntry::Ram(entry) => 1 + entry.serialized_size(compress),
        }
    }
}

impl<F: PrimeField> Valid for TranscriptEntry<F> {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            TranscriptEntry::Rom(entry) => entry.check(),
            TranscriptEntry::Ram(entry) => entry.check(),
        }
    }
}

impl<F: PrimeField> CanonicalDeserialize for TranscriptEntry<F> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            0u8 => RomTranscriptEntry::deserialize_with_mode(reader, compress, validate)
                .map(TranscriptEntry::Rom),
            1u8 => RamTranscriptEntry::deserialize_with_mode(reader, compress, validate)
                .map(TranscriptEntry::Ram),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

#[derive(Clone)]
pub enum TranscriptEntryVar<F: PrimeField> {
    Rom(RomTranscriptEntryVar<F>),
    Ram(RamTranscriptEntryVar<F>),
}

impl<F: PrimeField> TranscriptEntryVar<F> {
    pub fn is_padding(&self) -> Result<Boolean<F>, SynthesisError> {
        match self {
            TranscriptEntryVar::Rom(entry) => entry.is_padding(),
            TranscriptEntryVar::Ram(entry) => entry.is_padding(),
        }
    }
}

#[derive(Clone)]
pub enum RunningEvaluationVar<F: PrimeField> {
    Rom(RomRunningEvaluationVar<F>),
    Ram(RamRunningEvaluationVar<F>),
}

impl<F: PrimeField> RunningEvaluationVar<F> {
    pub fn set_challenges(&mut self, challenges: &[FpVar<F>]) {
        match self {
            RunningEvaluationVar::Rom(eval) => {
                assert_eq!(challenges.len(), 2);
                eval.challenges = Some((challenges[0].clone(), challenges[1].clone()));
            },
            RunningEvaluationVar::Ram(eval) => {
                assert_eq!(challenges.len(), 4);
                eval.challenges = Some((
                    challenges[0].clone(),
                    challenges[1].clone(),
                    challenges[2].clone(),
                    challenges[3].clone(),
                ));
            },
        }
    }
}

impl<F: PrimeField> ToConstraintField<F> for TranscriptEntry<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        match self {
            TranscriptEntry::Rom(entry) => entry.to_field_elements(),
            TranscriptEntry::Ram(entry) => entry.to_field_elements(),
        }
    }
}

/*
impl<F: PrimeField> ToConstraintFieldGadget<F> for RunningEvaluationVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        match self {
            RunningEvaluationVar::Rom(eval) => eval.to_constraint_field(),
            RunningEvaluationVar::Ram(eval) => eval.to_constraint_field(),
        }
    }
}
*/

impl<F: PrimeField> ToBytesGadget<F> for RunningEvaluationVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        match self {
            RunningEvaluationVar::Rom(eval) => eval.to_bytes(),
            RunningEvaluationVar::Ram(eval) => eval.to_bytes(),
        }
    }
}

impl<F: PrimeField> RunningEvaluationVar<F> {
    pub fn time_ordered_eval(&self) -> &FpVar<F> {
        match self {
            RunningEvaluationVar::Rom(eval) => &eval.time_ordered_eval,
            RunningEvaluationVar::Ram(eval) => &eval.time_ordered_eval,
        }
    }

    pub fn addr_ordered_eval(&self) -> &FpVar<F> {
        match self {
            RunningEvaluationVar::Rom(eval) => &eval.addr_ordered_eval,
            RunningEvaluationVar::Ram(eval) => &eval.addr_ordered_eval,
        }
    }
}

impl<F: PrimeField> R1CSVar<F> for RunningEvaluationVar<F> {
    type Value = RunningEvaluation<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        match self {
            RunningEvaluationVar::Rom(eval) => eval.cs(),
            RunningEvaluationVar::Ram(eval) => eval.cs(),
        }
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        match self {
            RunningEvaluationVar::Rom(eval) => Ok(RunningEvaluation::Rom(eval.value()?)),
            RunningEvaluationVar::Ram(eval) => Ok(RunningEvaluation::Ram(eval.value()?)),
        }
    }
}

impl<F: PrimeField> R1CSVar<F> for TranscriptEntryVar<F> {
    type Value = TranscriptEntry<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        match self {
            TranscriptEntryVar::Rom(entry) => entry.cs(),
            TranscriptEntryVar::Ram(entry) => entry.cs(),
        }
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        match self {
            TranscriptEntryVar::Rom(entry) => entry.value().map(TranscriptEntry::Rom),
            TranscriptEntryVar::Ram(entry) => entry.value().map(TranscriptEntry::Ram),
        }
    }
}

impl<F: PrimeField> ToBytesGadget<F> for TranscriptEntryVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        match self {
            TranscriptEntryVar::Rom(entry) => entry.to_bytes(),
            TranscriptEntryVar::Ram(entry) => entry.to_bytes(),
        }
    }
}

impl<F: PrimeField> AllocVar<RunningEvaluation<F>, F> for RunningEvaluationVar<F> {
    fn new_variable<T: Borrow<RunningEvaluation<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        match f()?.borrow() {
            RunningEvaluation::Rom(eval) => {
                RomRunningEvaluationVar::new_variable(cs, || Ok(eval), mode)
                    .map(RunningEvaluationVar::Rom)
            },
            RunningEvaluation::Ram(eval) => {
                RamRunningEvaluationVar::new_variable(cs, || Ok(eval), mode)
                    .map(RunningEvaluationVar::Ram)
            },
        }
    }
}

impl<F: PrimeField> AllocVar<TranscriptEntry<F>, F> for TranscriptEntryVar<F> {
    fn new_variable<T: Borrow<TranscriptEntry<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        match f()?.borrow() {
            TranscriptEntry::Rom(entry) => {
                RomTranscriptEntryVar::new_variable(cs, || Ok(entry), mode)
                    .map(TranscriptEntryVar::Rom)
            },
            TranscriptEntry::Ram(entry) => {
                RamTranscriptEntryVar::new_variable(cs, || Ok(entry), mode)
                    .map(TranscriptEntryVar::Ram)
            },
        }
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for TranscriptEntryVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        match self {
            TranscriptEntryVar::Rom(entry) => entry.to_constraint_field(),
            TranscriptEntryVar::Ram(entry) => entry.to_constraint_field(),
        }
    }
}
