use crate::portal_manager::PortalManager;
use crate::transcript::{
    RamRunningEvaluationVar, RamTranscriptEntry, RamTranscriptEntryVar, RunningEvaluationVar,
    TranscriptEntryVar,
};
use crate::uint32::Unsigned32;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::collections::HashMap;

use super::ProverPortalManager;

/*
 *
 * Section One: Address Manager
 *
 */

pub struct AddressManager {
    addresses: HashMap<String, u64>,
    current_address: u64,
}

impl AddressManager {
    // Constructor for AddressManager
    pub fn new() -> Self {
        AddressManager {
            addresses: HashMap::new(),
            current_address: 1, // We have to start at 1 because 0 is reserved for padding
        }
    }

    // Function to get the address by name or assign a new one
    pub fn name_to_addr(&mut self, name: &str) -> u64 {
        match self.addresses.get(name) {
            Some(&address) => address,
            None => {
                let address = self.current_address;
                self.addresses.insert(name.to_string(), address);
                self.current_address = self.current_address + 1;
                address
            },
        }
    }
}

/*
 *
 * Section Two: Setup Portal Manager
 *
 */

pub struct SetupRamPortalManager<F: PrimeField> {
    pub subtraces: Vec<Vec<RamTranscriptEntry<F>>>,
    pub address: AddressManager,
    pub time_index: Unsigned32,
    pub var_map: HashMap<String, F>,
    pub cs: ConstraintSystemRef<F>,
}

impl<F: PrimeField> SetupRamPortalManager<F> {
    pub fn new(cs: ConstraintSystemRef<F>) -> Self {
        SetupRamPortalManager {
            cs,
            address: AddressManager::new(),
            subtraces: Vec::new(),
            var_map: HashMap::new(),
            time_index: Unsigned32 {
                bits: vec![false; 32],
            },
        }
    }

    pub fn start_subtrace(&mut self, cs: ConstraintSystemRef<F>) {
        self.subtraces.push(Vec::new());
        self.cs = cs;
    }
}

impl<F: PrimeField> PortalManager<F> for SetupRamPortalManager<F> {
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Get the transcript entry corresponding to this variable
        let value = *self
            .var_map
            .get(name)
            .expect(&format!("cannot get portal wire '{name}'"));

        // Witness the value
        let val_var = FpVar::new_witness(ns!(self.cs, "wireval"), || Ok(value))?;

        // Add the entry to the time-ordered subtrace
        self.subtraces
            .last_mut()
            .expect("must run start_subtrace() before using SetupPortalManager")
            .push(RamTranscriptEntry {
                addr: self.address.name_to_addr(name),
                val: value,
                i: self.time_index.clone(),
                read: true,
            });

        self.time_index.increment_inplace();

        // Return the witnessed value
        Ok(val_var)
    }

    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        // update var_map
        self.var_map.insert(name.clone(), val.value()?);

        let entry = RamTranscriptEntry {
            addr: self.address.name_to_addr(&name),
            val: val.value().unwrap(),
            i: self.time_index.clone(),
            read: false,
        };
        // Increment time
        self.time_index.increment_inplace();

        // Log the concrete (not ZK) entry
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

pub struct RamProverPortalManager<F: PrimeField> {
    pub time_ordered_subtrace: Vec<RamTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace: Vec<RamTranscriptEntryVar<F>>,
    pub running_evals: RamRunningEvaluationVar<F>,
    pub next_entry_idx: usize,
}

impl<F: PrimeField> PortalManager<F> for RamProverPortalManager<F> {
    fn get(&mut self, _name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Get the next value
        let current_time_entry: &RamTranscriptEntryVar<F> = self
            .time_ordered_subtrace
            .get(self.next_entry_idx)
            .expect("ran out of time-ordered subtrace entries");

        let current_addr_entry = self
            .addr_ordered_subtrace
            .get(self.next_entry_idx + 1)
            .expect("ran out of addr-ordered subtrace entries");

        // Update the running polynomial
        self.running_evals.update_time_ordered(&current_time_entry);
        self.running_evals.update_addr_ordered(&current_addr_entry);

        // Get the next two values
        let next_time_entry = self.time_ordered_subtrace.get(self.next_entry_idx + 1);
        let next_addr_entry = self.addr_ordered_subtrace.get(self.next_entry_idx + 2);

        if !next_addr_entry.is_none() {
            let next_addr_entry = next_addr_entry.unwrap();
            // Addr-sorted bookkeeping
            // address is increasing or it is the same
            let is_addr_same = next_addr_entry.addr.is_eq(&current_addr_entry.addr)?;
            let is_addr_increasing = next_addr_entry
                .addr
                .is_eq(&(&current_addr_entry.addr + FpVar::one()))?;

            is_addr_same
                .or(&is_addr_increasing)?
                .enforce_equal(&Boolean::TRUE)?;

            // if address is increasing, it should be "write" and not "read"
            next_addr_entry
                .read
                .conditional_enforce_equal(&Boolean::FALSE, &is_addr_increasing)?;

            // if address is the same, and the second one is read, it should be equal to the previous entry
            let addr_same_and_next_is_read =
                is_addr_same.and(&next_addr_entry.read.is_eq(&Boolean::TRUE)?)?;

            next_addr_entry
                .val
                .conditional_enforce_equal(&current_addr_entry.val, &addr_same_and_next_is_read)?;

            // if address is the same, the next should have a higher timestamp
            next_addr_entry
                .i
                .is_greater_than(&current_addr_entry.i)
                .conditional_enforce_equal(&Boolean::TRUE, &is_addr_same)
                .expect("cmp error");
        }

        // Check timestamp if there's a next entry in the time-ordered subtrace
        if self.next_entry_idx < self.time_ordered_subtrace.len() - 1 {
            let next_time_entry = next_time_entry.unwrap();

            // time-ordered one being correct
            let mut t = current_time_entry.i.clone();
            // increment current_time and enforce equality
            t.increment_inplace();
            t.enforce_equal(&next_time_entry.i);
        }

        self.next_entry_idx += 1;
        // Return the val from the subtrace
        Ok(current_time_entry.val.clone())
    }

    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        let trace_val = self.get(&name)?;
        val.enforce_equal(&trace_val)?;
        Ok(())
    }

    fn running_evals(&self) -> RunningEvaluationVar<F> {
        RunningEvaluationVar::Ram(self.running_evals.clone())
    }
}

impl<F: PrimeField> ProverPortalManager<F> for RamProverPortalManager<F> {
    fn new(
        time_ordered_subtrace: Vec<TranscriptEntryVar<F>>,
        addr_ordered_subtrace: Vec<TranscriptEntryVar<F>>,
        running_evals: RunningEvaluationVar<F>,
    ) -> Self {
        let converted_time_subtrace = time_ordered_subtrace
            .into_iter()
            .map(|t| {
                if let TranscriptEntryVar::Ram(tt) = t {
                    tt
                } else {
                    panic!("cannot create a RAM portal manager from ROM transcript entries")
                }
            })
            .collect();
        let converted_addr_subtrace = addr_ordered_subtrace
            .into_iter()
            .map(|t| {
                if let TranscriptEntryVar::Ram(tt) = t {
                    tt
                } else {
                    panic!("cannot create a RAM portal manager from ROM transcript entries")
                }
            })
            .collect();
        let converted_running_evals = if let RunningEvaluationVar::Ram(e) = running_evals {
            e
        } else {
            panic!("cannot create a RAM portal manager from ROM running evals")
        };

        RamProverPortalManager {
            time_ordered_subtrace: converted_time_subtrace,
            addr_ordered_subtrace: converted_addr_subtrace,
            running_evals: converted_running_evals,
            next_entry_idx: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::portal_manager::ram_portal_manager::AddressManager;
    use crate::portal_manager::{PortalManager, RamProverPortalManager, SetupRamPortalManager};
    use crate::transcript::{RamRunningEvaluationVar, RamTranscriptEntry, RamTranscriptEntryVar};
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::ConstraintSystem;
    use num_traits::One;

    #[test]
    fn test_address_manager() {
        let mut address_manager = AddressManager::new();

        // Example usage
        let address1 = address_manager.name_to_addr("Alice");
        println!("Address for Alice: {}", address1);

        // Getting the same address for Alice
        let address2 = address_manager.name_to_addr("Alice");
        println!("Address for Alice: {}", address2);

        // Getting a new address for Bob
        let address3 = address_manager.name_to_addr("Bob");
        println!("Address for Bob: {}", address3);
    }

    #[test]
    fn test_ram() {
        let mut pm: SetupRamPortalManager<Fr> =
            SetupRamPortalManager::new(ConstraintSystem::new_ref());
        pm.start_subtrace(pm.cs.clone());
        for i in 0..1 {
            let fpvar = FpVar::new_witness(pm.cs.clone(), || Ok(Fr::from(i as i8))).unwrap();
            pm.set(format!("{}", i), &fpvar).expect("set error");
            let _ = pm.get(&format!("{}", i)).expect("get error");
            let _ = pm.get(&format!("{}", i)).expect("get error");
            pm.set(format!("{}", i), &fpvar).expect("set error");
            let _ = pm.get(&format!("{}", i)).expect("get error");
        }

        let time_based_array = pm.subtraces[0].clone();
        let mut time_based_array_var = Vec::new();
        for t in time_based_array {
            let t_var = RamTranscriptEntryVar::new_witness(pm.cs.clone(), || Ok(t)).unwrap();
            time_based_array_var.push(t_var);
        }

        // addr-sorted trace has an initial padding entry
        let mut addr_based_array = pm.subtraces[0].clone();
        addr_based_array.sort_by(|a, b| a.addr.cmp(&b.addr));
        addr_based_array.insert(0, RamTranscriptEntry::padding());

        let mut addr_based_array_var = Vec::new();
        for t in addr_based_array {
            let t_var = RamTranscriptEntryVar::new_witness(pm.cs.clone(), || Ok(t)).unwrap();
            addr_based_array_var.push(t_var);
        }

        let one_var = FpVar::new_witness(pm.cs.clone(), || Ok(Fr::one())).unwrap();
        let mut ram_prover = RamProverPortalManager {
            time_ordered_subtrace: time_based_array_var,
            addr_ordered_subtrace: addr_based_array_var,
            running_evals: RamRunningEvaluationVar {
                time_ordered_eval: one_var.clone(),
                addr_ordered_eval: one_var.clone(),
                challenges: Option::from((
                    one_var.clone(),
                    one_var.clone(),
                    one_var.clone(),
                    one_var.clone(),
                )),
            },
            next_entry_idx: 0,
        };

        for i in 0..1 {
            let fpvar = FpVar::new_witness(pm.cs.clone(), || Ok(Fr::from(i as i8))).unwrap();
            ram_prover.set(format!("{}", i), &fpvar).expect("set error");
            let _ = ram_prover.get(&format!("{}", i)).expect("get error");
            let _ = ram_prover.get(&format!("{}", i)).expect("get error");
            ram_prover.set(format!("{}", i), &fpvar).expect("set error");
            let _ = ram_prover.get(&format!("{}", i)).expect("get error");
            assert!(pm.cs.is_satisfied().unwrap());
            println!("{}", pm.cs.num_constraints());
        }

        // checking time evaluation == addr evaluation ==> both transcripts are permutations
        ram_prover
            .running_evals
            .time_ordered_eval
            .enforce_equal(&ram_prover.running_evals.addr_ordered_eval)
            .expect("TODO: panic message");
        assert!(pm.cs.is_satisfied().unwrap());
    }
}
