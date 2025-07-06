use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub const REGISTER_NUM: usize = 16;

#[derive(Clone)]
pub struct VirtualMachine<F: PrimeField> {
    pub data: [F; REGISTER_NUM],
    pub params: VirtualMachineParameters,
}

#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct VirtualMachineParameters {
    pub use_merkle_memory: bool,

    // number of subcircuits are 2 ^ log_num_subcircuit
    pub log_num_subcircuit: usize,

    pub dummy_constraint_num: usize,

    // it has to be a power of two
    pub operations_per_chunk: usize,
}

impl<F: PrimeField> VirtualMachine<F> {
    pub fn new(params: &VirtualMachineParameters) -> Self {
        VirtualMachine {
            data: [F::ZERO; REGISTER_NUM],
            params: VirtualMachineParameters {
                use_merkle_memory: params.use_merkle_memory,
                log_num_subcircuit: params.log_num_subcircuit,
                dummy_constraint_num: params.dummy_constraint_num,
                operations_per_chunk: params.operations_per_chunk,
            },
        }
    }

    pub fn execute_dummy_operation(&mut self) {}

    pub fn run(&mut self) {
        for _i in 0..(1 << self.params.log_num_subcircuit) * self.params.operations_per_chunk {
            self.execute_dummy_operation();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::vm::{VirtualMachine, VirtualMachineParameters};
    use ark_bn254::Fq;

    #[test]
    fn test_virtual_machine() {
        let virtual_machine_parameter = VirtualMachineParameters {
            use_merkle_memory: false,
            log_num_subcircuit: 5,
            dummy_constraint_num: 30,
            operations_per_chunk: 2,
        };
        let mut vm: VirtualMachine<Fq> = VirtualMachine::new(&virtual_machine_parameter);
        vm.run();
    }
}
