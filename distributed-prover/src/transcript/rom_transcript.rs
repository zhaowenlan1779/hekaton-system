use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::{R1CSVar, ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::borrow::Borrow;

use crate::aggregation::IppCom;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RomRunningEvaluation<F: PrimeField> {
    // Stored values that are updated
    pub time_ordered_eval: F,
    pub addr_ordered_eval: F,

    // Values specific to the global polynomial. These are need by the update function. Contains
    // `(entry_chal, tr_chal)`.
    pub challenges: Option<(F, F)>,
}

impl<F: PrimeField> Default for RomRunningEvaluation<F> {
    fn default() -> Self {
        RomRunningEvaluation {
            time_ordered_eval: F::one(),
            addr_ordered_eval: F::one(),
            challenges: None,
        }
    }
}

impl<F: PrimeField> RomRunningEvaluation<F> {
    /// Hash the trace commitment to calculate the challenges for the running eval
    /// TODO: Add a lot of context binding here. Don't want a weak fiat shamir
    pub fn new<E>(com: &IppCom<E>) -> RomRunningEvaluation<E::ScalarField>
    where
        E: Pairing<ScalarField = F>,
    {
        // Serialize the commitment to bytes
        let com_bytes = {
            let mut buf = Vec::new();
            com.serialize_uncompressed(&mut buf).unwrap();
            buf
        };

        // Generate two challenges by hashing com with two different context strings
        let entry_chal = {
            let mut hasher = Sha256::default();
            hasher.update(b"entry_chal");
            hasher.update(&com_bytes);
            hasher.finalize()
        };
        let tr_chal = {
            let mut hasher = Sha256::default();
            hasher.update(b"tr_chal");
            hasher.update(&com_bytes);
            hasher.finalize()
        };

        RomRunningEvaluation {
            time_ordered_eval: F::one(),
            addr_ordered_eval: F::one(),
            challenges: Some((
                F::from_le_bytes_mod_order(&entry_chal),
                F::from_le_bytes_mod_order(&tr_chal),
            )),
        }
    }

    /// Updates the running evaluation of the time-ordered transcript polyn
    pub(crate) fn update_time_ordered(&mut self, entry: &RomTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val + entry_chal * &F::from(entry.addr as u128);

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    pub(crate) fn update_addr_ordered(&mut self, entry: &RomTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val + entry_chal * &F::from(entry.addr as u128);

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

impl<F: PrimeField> ToConstraintField<F> for RomTranscriptEntry<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![F::from(self.addr as u128), self.val])
    }
}

#[derive(Clone)]
pub struct RomRunningEvaluationVar<F: PrimeField> {
    // Stored values that are updated
    pub time_ordered_eval: FpVar<F>,
    pub addr_ordered_eval: FpVar<F>,

    // Values specific to the global polynomial. These are need by the update function.
    // Specifically, this is (entry_chal, tr_chal). These are NOT inputted in the AllocVar impl
    pub challenges: Option<(FpVar<F>, FpVar<F>)>,
}

impl<F: PrimeField> RomRunningEvaluationVar<F> {
    /// Updates the running evaluation of the time-ordered transcript polyn
    pub fn update_time_ordered(&mut self, entry: &RomTranscriptEntryVar<F>) {
        let (entry_chal, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val + entry_chal * &entry.addr;

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entry)
        // evaluated at X = tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    pub fn update_addr_ordered(&mut self, entry: &RomTranscriptEntryVar<F>) {
        let (entry_chal, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val + entry_chal * &entry.addr;

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X = tr _ chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

impl<F: PrimeField> R1CSVar<F> for RomRunningEvaluationVar<F> {
    type Value = RomRunningEvaluation<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.time_ordered_eval.cs().or(self.addr_ordered_eval.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let challenges = self
            .challenges
            .as_ref()
            .map(|(a, b)| {
                a.value()
                    .and_then(|aa| b.value().and_then(|bb| Ok((aa, bb))))
            })
            .transpose()?;

        Ok(RomRunningEvaluation {
            time_ordered_eval: self.time_ordered_eval.value()?,
            addr_ordered_eval: self.addr_ordered_eval.value()?,
            challenges,
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for RomRunningEvaluationVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([
            self.time_ordered_eval.to_bytes()?,
            self.addr_ordered_eval.to_bytes()?,
        ]
        .concat())
    }
}

impl<F: PrimeField> AllocVar<RomRunningEvaluation<F>, F> for RomRunningEvaluationVar<F> {
    fn new_variable<T: Borrow<RomRunningEvaluation<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let evals = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let time_ordered_eval =
            FpVar::new_variable(ns!(cs, "time"), || evals.map(|e| e.time_ordered_eval), mode)?;
        let addr_ordered_eval =
            FpVar::new_variable(ns!(cs, "addr"), || evals.map(|e| e.addr_ordered_eval), mode)?;

        Ok(RomRunningEvaluationVar {
            time_ordered_eval,
            addr_ordered_eval,
            challenges: None,
        })
    }
}

/// An entry in the transcript of portal wire reads
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RomTranscriptEntry<F: PrimeField> {
    pub(crate) addr: u64,
    pub(crate) val: F,
}

impl<F: PrimeField> RomTranscriptEntry<F> {
    /// Returns an entry that always gets serialized as (0, 0). This is to pad the head of the
    /// address-sorted transcript
    pub(crate) fn padding() -> Self {
        RomTranscriptEntry {
            addr: 0,
            val: F::ZERO,
        }
    }
}

/// An entry in the transcript of portal wire reads
#[derive(Clone)]
pub struct RomTranscriptEntryVar<F: PrimeField> {
    pub val: FpVar<F>,
    /// The hash of the variable name
    pub addr: FpVar<F>,
}

impl<F: PrimeField> RomTranscriptEntryVar<F> {
    // Returns true iff this is a padding entry, i.e., addr = 0 and val = 0
    pub fn is_padding(&self) -> Result<Boolean<F>, SynthesisError> {
        self.addr
            .is_eq(&FpVar::zero())
            .and(self.addr.is_eq(&FpVar::zero()))
    }
}

impl<F: PrimeField> R1CSVar<F> for RomTranscriptEntryVar<F> {
    type Value = RomTranscriptEntry<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.val.cs().or(self.addr.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let addr_bytes = self.addr.value()?.into_bigint().to_bytes_le();

        // Check that the address fits into 64 bits
        assert!(addr_bytes.iter().skip(8).all(|&b| b == 0));

        // Copy addr into a fixed-size buffer
        let mut addr_buf = [0u8; 8];
        addr_buf.copy_from_slice(&addr_bytes[..8]);

        Ok(RomTranscriptEntry {
            val: self.val.value()?,
            addr: u64::from_le_bytes(addr_buf),
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for RomTranscriptEntryVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([self.addr.to_bytes()?, self.val.to_bytes()?].concat())
    }
}

impl<F: PrimeField> AllocVar<RomTranscriptEntry<F>, F> for RomTranscriptEntryVar<F> {
    fn new_variable<T: Borrow<RomTranscriptEntry<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let val = FpVar::new_variable(ns!(cs, "val"), || entry.map(|e| F::from(e.val)), mode)?;
        let addr = FpVar::new_variable(
            ns!(cs, "addr"),
            || entry.map(|e| F::from(e.addr as u128)),
            mode,
        )?;

        Ok(RomTranscriptEntryVar { val, addr })
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for RomTranscriptEntryVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![self.addr.clone(), self.val.clone()])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn running_eval_update_correctness() {
        let mut rng = test_rng();
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());

        let mut re = RomRunningEvaluation {
            time_ordered_eval: Fr::rand(&mut rng),
            addr_ordered_eval: Fr::rand(&mut rng),
            challenges: Some((Fr::rand(&mut rng), Fr::rand(&mut rng))),
        };
        let mut re_var = RomRunningEvaluationVar::new_constant(cs.clone(), &re).unwrap();
        re_var.challenges = Some((
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().0).unwrap(),
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().1).unwrap(),
        ));

        let entry = RomTranscriptEntry {
            addr: rng.gen(),
            val: Fr::rand(&mut rng),
        };
        let entry_var = RomTranscriptEntryVar::new_constant(cs.clone(), &entry).unwrap();
        re.update_time_ordered(&entry);
        re_var.update_time_ordered(&entry_var);

        let entry = RomTranscriptEntry {
            addr: rng.gen(),
            val: Fr::rand(&mut rng),
        };
        let entry_var = RomTranscriptEntryVar::new_constant(cs.clone(), &entry).unwrap();
        re.update_addr_ordered(&entry);
        re_var.update_addr_ordered(&entry_var);

        assert_eq!(re, re_var.value().unwrap());
    }
}
