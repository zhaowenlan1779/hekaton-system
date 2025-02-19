use crate::vm::VirtualMachine;
use ark_ff::PrimeField;

#[derive(Clone)]
pub struct Circuit {
    pub subcircuits: Vec<DummyCircuit>,
}

#[derive(Clone)]
pub struct DummyCircuit {}

pub fn vm_to_subcircuits<F: PrimeField>(vm: &VirtualMachine<F>) -> Vec<Circuit> {
    let mut circuits = Vec::new();
    let subcircuit_num = 1 << vm.params.log_num_subcircuit;
    // iterating through all operations
    for _i in 0..subcircuit_num {
        circuits.push(Circuit {
            subcircuits: vec![DummyCircuit {}; vm.params.operations_per_chunk],
        });
    }
    circuits
}
