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
use crate::uint32::*;

/*
 *
 * SECTION ONE, EVALUATION STRUCTS
 *
 */

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RamRunningEvaluation<F: PrimeField> {
    // Stored values that are updated
    pub time_ordered_eval: F,
    pub addr_ordered_eval: F,

    // Values specific to the global polynomial. These are need by the update function. Contains
    // `(entry_chal_1, entry_chal_2, entry_chal_3, tr_chal)`.
    pub challenges: Option<(F, F, F, F)>,
}

impl<F: PrimeField> Default for RamRunningEvaluation<F> {
    fn default() -> Self {
        RamRunningEvaluation {
            time_ordered_eval: F::one(),
            addr_ordered_eval: F::one(),
            challenges: None,
        }
    }
}

impl<F: PrimeField> RamRunningEvaluation<F> {
    /// Hash the trace commitment to calculate the challenges for the running eval
    /// TODO: Add a lot of context binding here. Don't want a weak fiat shamir
    pub fn new<E>(com: &IppCom<E>) -> RamRunningEvaluation<F>
    where
        E: Pairing<ScalarField = F>,
    {
        // Serialize the commitment to bytes
        let com_bytes = {
            let mut buf = Vec::new();
            com.serialize_uncompressed(&mut buf).unwrap();
            buf
        };

        // Generate four challenges by hashing com with two different context strings
        let entry_chal_1 = {
            let mut hasher = Sha256::default();
            hasher.update(b"entry_chal_1");
            hasher.update(&com_bytes);
            hasher.finalize()
        };
        let entry_chal_2 = {
            let mut hasher = Sha256::default();
            hasher.update(b"entry_chal_2");
            hasher.update(&com_bytes);
            hasher.finalize()
        };
        let entry_chal_3 = {
            let mut hasher = Sha256::default();
            hasher.update(b"entry_chal_3");
            hasher.update(&com_bytes);
            hasher.finalize()
        };
        let tr_chal = {
            let mut hasher = Sha256::default();
            hasher.update(b"tr_chal");
            hasher.update(&com_bytes);
            hasher.finalize()
        };

        RamRunningEvaluation {
            time_ordered_eval: F::one(),
            addr_ordered_eval: F::one(),
            challenges: Some((
                E::ScalarField::from_le_bytes_mod_order(&entry_chal_1),
                E::ScalarField::from_le_bytes_mod_order(&entry_chal_2),
                E::ScalarField::from_le_bytes_mod_order(&entry_chal_3),
                E::ScalarField::from_le_bytes_mod_order(&tr_chal),
            )),
        }
    }

    /// Updates the running evaluation of the time-ordered transcript polynomial
    pub fn update_time_ordered(&mut self, entry: &RamTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal_1, entry_chal_2, entry_chal_3, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val
            + entry_chal_1 * &F::from(entry.addr as u128)
            + entry_chal_2 * &F::from(u128::from(entry.i.representation()))
            + entry_chal_3 * &F::from(u128::from(entry.read));

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polynomial
    pub fn update_addr_ordered(&mut self, entry: &RamTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal_1, entry_chal_2, entry_chal_3, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // TODO: make sure it's consisted with RamRunningEvaluationVar
        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val
            + entry_chal_1 * &F::from(entry.addr as u128)
            + entry_chal_2 * &F::from(u128::from(entry.i.representation()))
            + entry_chal_3 * &F::from(u128::from(entry.read));

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X = tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

#[derive(Clone)]
pub struct RamRunningEvaluationVar<F: PrimeField> {
    // Stored values that are updated
    pub time_ordered_eval: FpVar<F>,
    pub addr_ordered_eval: FpVar<F>,

    // Values specific to the global polynomial. These are need by the update function.
    // (entry_chal_1, entry_chal_2, entry_chal_3 tr_chal): These are NOT inputted in the AllocVar impl
    pub challenges: Option<(FpVar<F>, FpVar<F>, FpVar<F>, FpVar<F>)>,
}

impl<F: PrimeField> RamRunningEvaluationVar<F> {
    /// Updates the running evaluation of the time-ordered transcript polyn
    pub fn update_time_ordered(&mut self, entry: &RamTranscriptEntryVar<F>) {
        let (entry_chal_1, entry_chal_2, entry_chal_3, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val
            + entry_chal_1 * &entry.addr
            + entry_chal_2 * &Boolean::le_bits_to_fp_var(&entry.i.bits).unwrap()
            + entry_chal_3 * &FpVar::from(entry.read.clone());

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entry)
        // evaluated at X = tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    pub fn update_addr_ordered(&mut self, entry: &RamTranscriptEntryVar<F>) {
        let (entry_chal_1, entry_chal_2, entry_chal_3, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val
            + entry_chal_1 * &entry.addr
            + entry_chal_2 * &Boolean::le_bits_to_fp_var(&entry.i.bits).unwrap()
            + entry_chal_3 * &FpVar::from(entry.read.clone());

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entry)
        // evaluated at X = tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

impl<F: PrimeField> R1CSVar<F> for RamRunningEvaluationVar<F> {
    type Value = RamRunningEvaluation<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.time_ordered_eval.cs().or(self.addr_ordered_eval.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let challenges = self
            .challenges
            .as_ref()
            .map(|(a, b, c, d)| {
                a.value().and_then(|aa| {
                    b.value().and_then(|bb| {
                        c.value()
                            .and_then(|cc| d.value().and_then(|dd| Ok((aa, bb, cc, dd))))
                    })
                })
            })
            .transpose()?;

        Ok(RamRunningEvaluation {
            time_ordered_eval: self.time_ordered_eval.value()?,
            addr_ordered_eval: self.addr_ordered_eval.value()?,
            challenges,
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for RamRunningEvaluationVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([
            self.time_ordered_eval.to_bytes()?,
            self.addr_ordered_eval.to_bytes()?,
        ]
        .concat())
    }
}

impl<F: PrimeField> AllocVar<RamRunningEvaluation<F>, F> for RamRunningEvaluationVar<F> {
    fn new_variable<T: Borrow<RamRunningEvaluation<F>>>(
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

        Ok(RamRunningEvaluationVar {
            time_ordered_eval,
            addr_ordered_eval,
            challenges: None,
        })
    }
}

/*
 *
 * SECTION TWO, RAM TRANSCRIPT
 *
 */

/// An entry in the transcript of portal wire reads
#[derive(Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RamTranscriptEntry<F: PrimeField> {
    pub addr: u64,
    pub val: F,
    pub i: Unsigned32,
    pub read: bool,
}

impl<F: PrimeField> RamTranscriptEntry<F> {
    pub fn padding() -> Self {
        RamTranscriptEntry {
            addr: 0,
            val: F::ZERO,
            i: Unsigned32::default(),
            read: false,
        }
    }
}

impl<F: PrimeField> ToConstraintField<F> for RamTranscriptEntry<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![
            F::from(self.addr as u128),
            self.val,
            self.i.as_field_elem(),
            F::from(self.read as u128),
        ])
    }
}

#[derive(Clone)]
pub struct RamTranscriptEntryVar<F: PrimeField> {
    pub addr: FpVar<F>,
    pub val: FpVar<F>,
    pub i: Unsigned32Var<F>,
    pub read: Boolean<F>,
}

impl<F: PrimeField> RamTranscriptEntryVar<F> {
    // Returns true iff this is a padding entry, i.e., all fields are 0
    pub fn is_padding(&self) -> Result<Boolean<F>, SynthesisError> {
        self.addr
            .is_eq(&FpVar::zero())
            .and(self.addr.is_eq(&FpVar::zero()))
            .and(self.i.to_fpvar()?.is_eq(&FpVar::zero()))
            .and(self.read.is_eq(&Boolean::FALSE))
    }
}

impl<F: PrimeField> R1CSVar<F> for RamTranscriptEntryVar<F> {
    type Value = RamTranscriptEntry<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.val
            .cs()
            .or(self.addr.cs())
            .or(self.read.cs())
            .or(self.i.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let addr_bytes = self.addr.value()?.into_bigint().to_bytes_le();

        // Check that the address fits into 64 bits
        assert!(addr_bytes.iter().skip(8).all(|&b| b == 0));

        // Copy addr into a fixed-size buffer
        let mut addr_buf = [0u8; 8];
        addr_buf.copy_from_slice(&addr_bytes[..8]);

        Ok(RamTranscriptEntry {
            val: self.val.value()?,
            i: self.i.value()?,
            addr: u64::from_le_bytes(addr_buf),
            read: self.read.value()?,
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for RamTranscriptEntryVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([
            self.addr.to_bytes()?,
            self.val.to_bytes()?,
            self.i.to_bytes()?,
            self.read.to_bytes()?,
        ]
        .concat())
    }
}

impl<F: PrimeField> AllocVar<RamTranscriptEntry<F>, F> for RamTranscriptEntryVar<F> {
    fn new_variable<T: Borrow<RamTranscriptEntry<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let val = FpVar::new_variable(ns!(cs, "val"), || entry.map(|e| e.val), mode)?;
        let addr = FpVar::new_variable(
            ns!(cs, "addr"),
            || entry.map(|e| F::from(e.addr as u128)),
            mode,
        )?;
        let i = Unsigned32Var::new_variable(ns!(cs, "i"), || entry.map(|e| e.i.clone()), mode)?;
        let read = Boolean::new_variable(ns!(cs, "read"), || entry.map(|e| e.read), mode)?;

        Ok(RamTranscriptEntryVar { val, i, addr, read })
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for RamTranscriptEntryVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![
            self.addr.clone(),
            self.val.clone(),
            self.i.to_fpvar()?,
            self.read.clone().into(),
        ])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::test_rng;
    use num_traits::{One, Zero};
    use rand::random;

    #[test]
    fn running_eval_update_correctness() {
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());
        let ram_transcript = RamTranscriptEntry {
            addr: 0,
            val: Fr::zero(),
            i: Unsigned32::default(),
            read: true,
        };

        let ram_var = RamTranscriptEntryVar::new_variable(
            cs.clone(),
            || Ok(ram_transcript.clone()),
            AllocationMode::Constant,
        )
        .unwrap();
        let ram_transcript_2 = RamTranscriptEntryVar::value(&ram_var).unwrap();
        println!("{:?}", ram_transcript_2);
        assert_eq!(ram_transcript, ram_transcript_2);
    }

    #[test]
    fn running_evaluation_update_correctness() {
        let mut rng = test_rng();
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());

        let mut re = RamRunningEvaluation {
            time_ordered_eval: Fr::rand(&mut rng),
            addr_ordered_eval: Fr::rand(&mut rng),
            challenges: Option::from((
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
            )),
        };

        let mut re_var = RamRunningEvaluationVar::new_constant(cs.clone(), &re).unwrap();
        re_var.challenges = Option::from((
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().0).unwrap(),
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().1).unwrap(),
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().2).unwrap(),
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().3).unwrap(),
        ));

        let bits: Vec<bool> = (0..32).map(|_| random::<bool>()).collect();
        let entry = RamTranscriptEntry {
            addr: u64::rand(&mut rng),
            val: Fr::one(),
            i: Unsigned32 { bits },
            read: true,
        };
        let entry_var = RamTranscriptEntryVar::new_constant(cs.clone(), &entry).unwrap();
        re.update_time_ordered(&entry);
        re_var.update_time_ordered(&entry_var);

        let bits: Vec<bool> = (0..32).map(|_| random::<bool>()).collect();
        let entry = RamTranscriptEntry {
            addr: u64::rand(&mut rng),
            val: Fr::one(),
            i: Unsigned32 { bits },
            read: true,
        };
        let entry_var = RamTranscriptEntryVar::new_constant(cs.clone(), &entry).unwrap();
        re.update_addr_ordered(&entry);
        re_var.update_addr_ordered(&entry_var);

        assert_eq!(re, re_var.value().unwrap());
    }
}
