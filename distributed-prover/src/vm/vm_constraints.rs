use crate::portal_manager::{PortalManager, RamProverPortalManager, SetupRamPortalManager};
use crate::transcript::{MemType, TranscriptEntry};
use crate::vm::memory::Memory;
use crate::vm::{VirtualMachine, VirtualMachineParameters, REGISTER_NUM};
use crate::CircuitWithPortals;
use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use rand::Rng;
use std::marker::PhantomData;
use std::ops::Mul;

impl CircuitWithPortals<Fr> for VirtualMachine<Fr> {
    type Parameters = VirtualMachineParameters;
    type ProverPortalManager = RamProverPortalManager<Fr>;
    const MEM_TYPE: MemType = MemType::Ram;

    /// Makes a random instance of this circuit. This is just new()
    fn rand(_: &mut impl Rng, params: &VirtualMachineParameters) -> Self {
        Self::new(params)
    }

    fn get_params(&self) -> Self::Parameters {
        self.params
    }

    fn get_portal_subtraces(&self) -> Vec<Vec<TranscriptEntry<Fr>>> {
        let cs = ConstraintSystem::new_ref();
        let mut pm = SetupRamPortalManager::new(cs.clone());
        for subcircuit_idx in 0..self.num_subcircuits() {
            pm.start_subtrace(cs.clone());
            if subcircuit_idx != 0 {
                // get the registers
                for i in 0..REGISTER_NUM {
                    let _ = pm.get(&format!("register {i}"));
                }
                // do the dummy operation
                for _ in 0..self.params.operations_per_chunk {
                    let _ = pm.set(
                        format!("register 1"),
                        &FpVar::new_witness(cs.clone(), || Ok(Fr::ONE)).unwrap(),
                    );
                    let _ = pm.get(&format!("register 1"));
                    let _ = pm.get(&format!("register 1"));
                }
                // write the resulting registers to pm
                for i in 0..REGISTER_NUM {
                    let _ = pm.set(
                        format!("register {i}"),
                        &FpVar::new_witness(cs.clone(), || Ok(Fr::ONE)).unwrap(),
                    );
                }
            } else {
                // write the initial registers
                for i in 0..REGISTER_NUM {
                    let _ = pm.set(
                        format!("register {i}"),
                        &FpVar::new_witness(cs.clone(), || Ok(Fr::ONE)).unwrap(),
                    );
                }
                // do the dummy operation
                for _ in 0..self.params.operations_per_chunk {
                    let _ = pm.set(
                        format!("register 1"),
                        &FpVar::new_witness(cs.clone(), || Ok(Fr::ONE)).unwrap(),
                    );
                    let _ = pm.get(&format!("register 1"));
                    let _ = pm.get(&format!("register 1"));
                }
            }
        }

        // Return the subtraces, wrapped appropriately
        pm.subtraces
            .into_iter()
            .map(|subtrace| {
                subtrace
                    .into_iter()
                    .map(|e| TranscriptEntry::Ram(e))
                    .collect()
            })
            .collect()
    }

    fn num_subcircuits(&self) -> usize {
        1 << self.params.log_num_subcircuit
    }

    fn get_unique_subcircuits(&self) -> Vec<usize> {
        vec![0, 1]
    }

    fn representative_subcircuit(&self, subcircuit_idx: usize) -> usize {
        return if subcircuit_idx == 0 { 0 } else { 1 };
    }

    fn new(params: &Self::Parameters) -> Self {
        VirtualMachine::new(params)
    }

    fn get_serialized_witnesses(&self, _subcircuit_idx: usize) -> Vec<u8> {
        Vec::new()
    }

    fn set_serialized_witnesses(&mut self, _subcircuit_idx: usize, _bytes: &[u8]) {}

    fn generate_constraints<P: PortalManager<Fr>>(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let starting_num_constraints = cs.num_constraints();
        // set memory struct
        let mut memory = Memory {
            use_merkle_memory: self.params.use_merkle_memory,
            portal_manager: pm,
            phantom: PhantomData,
        };
        // subcircuit_idx == 0 ==> write registers to memory otherwise dummy variable
        if subcircuit_idx != 0 {
            // get the registers
            get_registers(&mut memory, cs.clone());
            // do the dummy operation
            do_dummy_operation(
                self,
                cs.clone(),
                self.params.dummy_constraint_num,
                &mut memory,
            );
            // write the resulting registers to pm
            set_registers(&mut memory, cs.clone());
        } else {
            // write the initial registers
            set_registers(&mut memory, cs.clone());
            do_dummy_operation(
                self,
                cs.clone(),
                self.params.dummy_constraint_num,
                &mut memory,
            );
        }
        let ending_num_constraints = cs.num_constraints();
        println!(
            "Test subcircuit {subcircuit_idx} costs {} constraints",
            ending_num_constraints - starting_num_constraints
        );
        Ok(())
    }
}

pub fn get_registers<P: PortalManager<Fr>>(memory: &mut Memory<P>, cs: ConstraintSystemRef<Fr>) {
    for i in 0..REGISTER_NUM {
        let _ = memory.get(&format!("register {i}"), cs.clone());
    }
}

pub fn set_registers<P: PortalManager<Fr>>(memory: &mut Memory<P>, cs: ConstraintSystemRef<Fr>) {
    for i in 0..REGISTER_NUM {
        let _ = memory.set(
            format!("register {i}"),
            &FpVar::new_witness(cs.clone(), || Ok(Fr::ONE)).unwrap(),
            cs.clone(),
        );
    }
}

pub fn do_dummy_operation<P: PortalManager<Fr>>(
    vm: &mut VirtualMachine<Fr>,
    cs: ConstraintSystemRef<Fr>,
    dummy_constraint_num: usize,
    memory: &mut Memory<P>,
) {
    for _ in 0usize..vm.params.operations_per_chunk {
        // memory operations
        let _ = memory.set(
            "register 1".to_string(),
            &FpVar::new_witness(cs.clone(), || Ok(Fr::ONE)).unwrap(),
            cs.clone(),
        );
        let _ = memory.get(&"register 1".to_string(), cs.clone());
        let _ = memory.get(&"register 1".to_string(), cs.clone());
        // do some dummy operation
        for _ in 0..dummy_constraint_num / 2 {
            let fp1 = FpVar::new_witness(cs.clone(), || Ok(Fr::from(12u128))).unwrap();
            let fp2 = FpVar::new_witness(cs.clone(), || Ok(Fr::from(12u128))).unwrap();
            let _ = fp1.mul(fp2);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::portal_manager::SetupRamPortalManager;
    use crate::transcript::TranscriptEntry;
    use crate::vm::{VirtualMachine, VirtualMachineParameters};
    use crate::CircuitWithPortals;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_vm() {
        let virtual_machine_parameter = VirtualMachineParameters {
            use_merkle_memory: false,
            log_num_subcircuit: 3,
            dummy_constraint_num: 30,
            operations_per_chunk: 2,
        };
        let mut vm: VirtualMachine<Fr> = VirtualMachine::new(&virtual_machine_parameter);
        let expected_subtraces = vm.get_portal_subtraces();

        // initializing the portal manager
        let mut pm: SetupRamPortalManager<Fr> =
            SetupRamPortalManager::new(ConstraintSystem::new_ref());
        let cs = pm.cs.clone();
        for subcircuit_idx in 0..vm.num_subcircuits() {
            pm.start_subtrace(cs.clone());
            vm.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                .unwrap();
        }
        assert!(pm.cs.is_satisfied().unwrap());
        println!("num_constraints: {}", cs.num_constraints());

        if !virtual_machine_parameter.use_merkle_memory {
            // Compare the subtraces
            let wrapped_subtraces = pm
                .subtraces
                .into_iter()
                .map(|st| {
                    st.into_iter()
                        .map(|e| TranscriptEntry::Ram(e))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            assert_eq!(wrapped_subtraces, expected_subtraces);
        }
    }
}
