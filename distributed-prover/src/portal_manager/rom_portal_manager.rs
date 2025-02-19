use ark_std::collections::HashMap;

use crate::portal_manager::PortalManager;
use crate::transcript::{
    RomRunningEvaluationVar, RomTranscriptEntry, RomTranscriptEntryVar, RunningEvaluationVar,
    TranscriptEntryVar,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

use super::ProverPortalManager;

/*
*
*
   Rom portal manager was initially implemented and then completed by a separate (but similar)
   ram portal manager, read both for a better understanding of how it works.
*
*
*/

/// This portal manager is used by the coordinator to produce the trace
pub struct SetupRomPortalManager<F: PrimeField> {
    /// All the subtraces from the full run of the circuit
    pub subtraces: Vec<Vec<RomTranscriptEntry<F>>>,

    /// The address that this manager will assign to the next unseen variable name
    next_var_addr: u64,

    /// A map from variable names to their transcript entry
    var_map: HashMap<String, RomTranscriptEntry<F>>,

    pub(crate) cs: ConstraintSystemRef<F>,
}

impl<F: PrimeField> SetupRomPortalManager<F> {
    pub fn new(cs: ConstraintSystemRef<F>) -> Self {
        SetupRomPortalManager {
            cs,
            next_var_addr: 1, // We have to start at 1 because 0 is reserved for padding
            subtraces: Vec::new(),
            var_map: HashMap::new(),
        }
    }

    /// Makes a subtrace and updates the constraint system. The constraint system needs to be
    /// updated with an empty one otherwise it gets too big and we run out of memory
    pub fn start_subtrace(&mut self, cs: ConstraintSystemRef<F>) {
        self.subtraces.push(Vec::new());
        self.cs = cs;
    }
}

impl<F: PrimeField> PortalManager<F> for SetupRomPortalManager<F> {
    /// Gets the value from the map, witnesses it, and adds the entry to the trace
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Get the transcript entry corresponding to this variable
        let entry = *self
            .var_map
            .get(name)
            .expect(&format!("cannot get portal wire '{name}'"));

        // Witness the value
        let val_var = FpVar::new_witness(ns!(self.cs, "wireval"), || Ok(entry.val))?;

        // Add the entry to the time-ordered subtrace
        self.subtraces
            .last_mut()
            .expect("must run start_subtrace() before using SetupPortalManager")
            .push(entry);

        // Return the witnessed value
        Ok(val_var)
    }

    /// Sets the value in the map and adds the entry to the trace
    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        // This is ROM. You cannot overwrite values
        assert!(
            self.var_map.get(&name).is_none(),
            "cannot set portal wire more than once; wire '{name}'"
        );

        // Make a new transcript entry. Use a fresh address
        let entry = RomTranscriptEntry {
            val: val.value().unwrap(),
            addr: self.next_var_addr,
        };
        // Increment to the next unused address
        self.next_var_addr += 1;

        // Log the concrete (not ZK) entry
        self.var_map.insert(name.to_string(), entry);
        self.subtraces
            .last_mut()
            .expect("must run start_subtrace() before using SetupPortalManager")
            .push(entry);

        Ok(())
    }

    fn running_evals(&self) -> RunningEvaluationVar<F> {
        // A setup portal manager does not have running evals
        unimplemented!()
    }
}

/// This portal manager is used by a subcircuit prover. It takes the subtrace for this subcircuit as
/// well as the running evals up until this point. These values are used in the CircuitWithPortals
/// construction later.
pub struct RomProverPortalManager<F: PrimeField> {
    pub time_ordered_subtrace: Vec<RomTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace: Vec<RomTranscriptEntryVar<F>>,
    pub running_evals: RomRunningEvaluationVar<F>,
    pub next_entry_idx: usize,
}

impl<F: PrimeField> PortalManager<F> for RomProverPortalManager<F> {
    /// Gets the next subtrace elem, updates the running polynomial evals to reflect the read op, and
    /// does one step of the name-ordered coherence check.
    fn get(&mut self, _name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Get the next value
        let current_time_entry = self
            .time_ordered_subtrace
            .get(self.next_entry_idx)
            .expect("ran out of time-ordered subtrace entries");
        let current_addr_entry = self
            .addr_ordered_subtrace
            .get(self.next_entry_idx)
            .expect("ran out of addr-ordered subtrace entries");

        // Update the running polynomial
        self.running_evals.update_time_ordered(&current_time_entry);

        // Get the next two values. Unpack both
        let next_addr_entry = self
            .addr_ordered_subtrace
            .get(self.next_entry_idx + 1)
            .unwrap();
        let (next_addr, next_val) = (&next_addr_entry.addr, &next_addr_entry.val);

        // Check cur_addr <= next_addr. In fact, next_addr is guaranteed to be cur_addr + 1 if not equal
        let is_addr_same = next_addr.is_eq(&current_addr_entry.addr)?;
        let is_addr_increasing = next_addr.is_eq(&(&current_addr_entry.addr + FpVar::one()))?;
        is_addr_same
            .or(&is_addr_increasing)?
            .enforce_equal(&Boolean::TRUE)?;

        // Check current_val == next_val if cur_addr == next_addr
        current_addr_entry
            .val
            .conditional_enforce_equal(next_val, &is_addr_same)?;

        // Update the index into the trace(s)
        self.next_entry_idx += 1;

        // Update the addr running eval
        self.running_evals.update_addr_ordered(&next_addr_entry);

        // Return the val from the subtrace
        Ok(current_time_entry.val.clone())
    }

    /// Set is no different from get in circuit land. This does the same thing, and also enforce
    /// that `val` equals the popped subtrace value.
    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        let trace_val = self.get(&name)?;
        val.enforce_equal(&trace_val)?;
        Ok(())
    }

    fn running_evals(&self) -> RunningEvaluationVar<F> {
        RunningEvaluationVar::Rom(self.running_evals.clone())
    }
}

impl<F: PrimeField> ProverPortalManager<F> for RomProverPortalManager<F> {
    fn new(
        time_ordered_subtrace: Vec<TranscriptEntryVar<F>>,
        addr_ordered_subtrace: Vec<TranscriptEntryVar<F>>,
        running_evals: RunningEvaluationVar<F>,
    ) -> Self {
        let converted_time_subtrace = time_ordered_subtrace
            .into_iter()
            .map(|t| {
                if let TranscriptEntryVar::Rom(tt) = t {
                    tt
                } else {
                    panic!("cannot create a ROM portal manager from RAM transcript entries")
                }
            })
            .collect();
        let converted_addr_subtrace = addr_ordered_subtrace
            .into_iter()
            .map(|t| {
                if let TranscriptEntryVar::Rom(tt) = t {
                    tt
                } else {
                    panic!("cannot create a ROM portal manager from RAM transcript entries")
                }
            })
            .collect();
        let converted_running_evals = if let RunningEvaluationVar::Rom(e) = running_evals {
            e
        } else {
            panic!("cannot create a RAM portal manager from ROM running evals")
        };

        RomProverPortalManager {
            time_ordered_subtrace: converted_time_subtrace,
            addr_ordered_subtrace: converted_addr_subtrace,
            running_evals: converted_running_evals,
            next_entry_idx: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::portal_manager::{PortalManager, RomProverPortalManager, SetupRomPortalManager};
    use crate::transcript::{RomRunningEvaluationVar, RomTranscriptEntry, RomTranscriptEntryVar};
    use ark_bls12_381::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::ConstraintSystem;
    use num_traits::One;

    #[test]
    fn test_rom() {
        let mut pm: SetupRomPortalManager<Fr> =
            SetupRomPortalManager::new(ConstraintSystem::new_ref());
        pm.start_subtrace(pm.cs.clone());
        for i in 0usize..10 {
            if i != 0 {
                let _ = pm.get(&format!("{}", i - 1)).unwrap();
            }
            let fpvar = FpVar::new_witness(pm.cs.clone(), || Ok(Fr::from(i as i8))).unwrap();
            pm.set(format!("{}", i), &fpvar).expect("set error");
        }

        let time_based_array = pm.subtraces[0].clone();
        let mut time_based_array_var = Vec::new();
        for t in time_based_array {
            let t_var = RomTranscriptEntryVar::new_witness(pm.cs.clone(), || Ok(t)).unwrap();
            time_based_array_var.push(t_var);
        }

        // addr-sorted trace has an initial padding entry
        let mut addr_based_array = pm.subtraces[0].clone();
        addr_based_array.sort_by(|a, b| a.addr.cmp(&b.addr));
        addr_based_array.insert(0, RomTranscriptEntry::padding());

        let mut addr_based_array_var = Vec::new();
        for t in addr_based_array {
            let t_var = RomTranscriptEntryVar::new_witness(pm.cs.clone(), || Ok(t)).unwrap();
            addr_based_array_var.push(t_var);
        }

        let one_var = FpVar::new_witness(pm.cs.clone(), || Ok(Fr::one())).unwrap();
        let mut rom_prover = RomProverPortalManager {
            time_ordered_subtrace: time_based_array_var,
            addr_ordered_subtrace: addr_based_array_var,
            running_evals: RomRunningEvaluationVar {
                time_ordered_eval: one_var.clone(),
                addr_ordered_eval: one_var.clone(),
                challenges: Option::from((one_var.clone(), one_var.clone())),
            },
            next_entry_idx: 0,
        };

        for i in 0usize..10 {
            if i != 0 {
                let _ = rom_prover.get(&format!("{}", i - 1)).unwrap();
            }
            let fpvar = FpVar::new_witness(pm.cs.clone(), || Ok(Fr::from(i as i8))).unwrap();
            rom_prover.set(format!("{}", i), &fpvar).expect("set error");
            println!("{}", pm.cs.num_constraints());
        }
        // checking time evaluation == addr evaluation ==> both transcripts are permutations
        rom_prover
            .running_evals
            .time_ordered_eval
            .enforce_equal(&rom_prover.running_evals.addr_ordered_eval)
            .expect("TODO: panic message");
        assert!(pm.cs.is_satisfied().unwrap());
    }
}
