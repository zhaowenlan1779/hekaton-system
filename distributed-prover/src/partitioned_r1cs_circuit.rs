use crate::{
    portal_manager::{PortalManager, RomProverPortalManager, SetupRomPortalManager},
    transcript::{MemType, TranscriptEntry},
    CircuitWithPortals,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSystem, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circom_compat::{read_witness, R1CSFile};
use rand::Rng;
use rayon::prelude::*;
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

#[derive(Clone)]
pub struct PartitionedR1CSCircuit<F: PrimeField> {
    pub params: PartitionedR1CSCircuitParams,
    pub r1cs: Vec<R1CSFile<F>>,
    // (owned_portals, borrowed_portals)
    pub shared_wires: Vec<(Vec<usize>, Vec<usize>)>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PartitionedR1CSCircuitParams {
    pub num_subcircuits: usize,
    pub file_path: String,
}

impl<F: PrimeField> CircuitWithPortals<F> for PartitionedR1CSCircuit<F> {
    type Parameters = PartitionedR1CSCircuitParams;
    const MEM_TYPE: MemType = MemType::Rom;
    type ProverPortalManager = RomProverPortalManager<F>;

    fn num_subcircuits(&self) -> usize {
        self.params.num_subcircuits
    }

    /// Returns a minimal set of the unique subcircuits in this circuit. This is for CRS generation.
    fn get_unique_subcircuits(&self) -> Vec<usize> {
        (0..self.params.num_subcircuits).collect()
    }

    /// Maps a subcircuit index to its canonical representative in the list of unique subcircuits returned by `get_unique_subcircuits`.
    fn representative_subcircuit(&self, subcircuit_idx: usize) -> usize {
        subcircuit_idx
    }

    fn get_params(&self) -> PartitionedR1CSCircuitParams {
        self.params.clone()
    }

    /// Makes a Merkle tree with a random set of leaves. The size is given by `params`
    fn rand(_rng: &mut impl Rng, params: &PartitionedR1CSCircuitParams) -> Self {
        Self::new(params)
    }

    // Make a new empty merkle tree circuit
    fn new(params: &Self::Parameters) -> Self {
        let (r1cs, shared_wires): (Vec<_>, Vec<_>) = (0..params.num_subcircuits)
            .into_par_iter()
            .map(|i| {
                let reader =
                    BufReader::new(File::open(format!("{}.{}.r1cs", params.file_path, i)).unwrap());
                let mut file = R1CSFile::<F>::new(reader).unwrap();

                let witness_reader =
                    BufReader::new(File::open(format!("{}.{}.json", params.file_path, i)).unwrap());
                file.witness = read_witness::<F>(witness_reader);

                let meta_reader =
                    BufReader::new(File::open(format!("{}.{}.meta", params.file_path, i)).unwrap());
                let mut lines = meta_reader.lines();
                let first_line = lines.next().unwrap().unwrap();
                let first_line_integers = first_line
                    .split(' ')
                    .flat_map(str::parse::<usize>)
                    .collect::<Vec<_>>();
                let num_owned_portals = first_line_integers[1];
                let mut variables = lines
                    .map(|line| line.unwrap().parse::<usize>().unwrap())
                    .collect::<Vec<_>>();
                let borrowed_portals = variables.split_off(num_owned_portals);
                (file, (variables, borrowed_portals))
            })
            .unzip();

        Self {
            params: params.clone(),
            r1cs,
            shared_wires,
        }
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        let mut out_buf = Vec::new();
        CanonicalSerialize::serialize_uncompressed(
            &self.r1cs[subcircuit_idx].witness,
            &mut out_buf,
        )
        .unwrap();
        out_buf
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        self.r1cs[subcircuit_idx].witness =
            Vec::<F>::deserialize_uncompressed_unchecked(bytes).unwrap();
    }

    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let starting_num_constraints = cs.num_constraints();

        let r1cs = &self.r1cs[subcircuit_idx];
        let (owned_portals, borrowed_portals) = &self.shared_wires[subcircuit_idx];
        let num_unique_variables =
            r1cs.header.n_wires as usize - owned_portals.len() - borrowed_portals.len();
        let mut variables = (0..num_unique_variables)
            .map(|i| {
                if i == 0 {
                    FpVar::Constant(F::ONE)
                } else {
                    FpVar::new_witness(cs.clone(), || Ok(r1cs.witness[i])).unwrap()
                }
            })
            .chain(owned_portals.iter().enumerate().map(|(i, var_index)| {
                let variable =
                    FpVar::new_witness(cs.clone(), || Ok(r1cs.witness[num_unique_variables + i]))
                        .unwrap();
                pm.set(format!("var{}", var_index), &variable).unwrap();
                variable
            }))
            .collect::<Vec<_>>();
        variables.extend(
            borrowed_portals
                .iter()
                .map(|var_index| pm.get(&format!("var{}", var_index)).unwrap()),
        );

        let make_lc = |lc_data: &[(usize, F)]| {
            lc_data.iter().fold(
                LinearCombination::<F>::zero(),
                |lc: LinearCombination<F>, (index, coeff)| match &variables[*index] {
                    FpVar::Var(var) => lc + (*coeff, var.variable),
                    FpVar::Constant(constant) => lc + (*coeff * *constant, Variable::One),
                },
            )
        };
        for constraint in &r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.0),
                make_lc(&constraint.1),
                make_lc(&constraint.2),
            )?;
        }

        let ending_num_constraints = cs.num_constraints();
        println!(
            "Test subcircuit {subcircuit_idx} costs {} constraints",
            ending_num_constraints - starting_num_constraints
        );
        Ok(())
    }

    // This produces the same portal trace as generate_constraints(0...num_circuits) would do, but
    // without having to do all the ZK SHA2 computations
    fn get_portal_subtraces(&self) -> Vec<Vec<TranscriptEntry<F>>> {
        // Make a portal manager to collect the subtraces
        let cs = ConstraintSystem::new_ref();
        let mut pm = SetupRomPortalManager::new(cs.clone());

        for subcircuit_idx in 0..self.params.num_subcircuits {
            pm.start_subtrace(ConstraintSystem::new_ref());

            let r1cs = &self.r1cs[subcircuit_idx];
            let (owned_portals, borrowed_portals) = &self.shared_wires[subcircuit_idx];
            let num_unique_variables =
                r1cs.header.n_wires as usize - owned_portals.len() - borrowed_portals.len();
            owned_portals.iter().enumerate().for_each(|(i, var_index)| {
                let variable =
                    FpVar::new_witness(cs.clone(), || Ok(r1cs.witness[num_unique_variables + i]))
                        .unwrap();
                pm.set(format!("var{}", var_index), &variable).unwrap();
            });
            borrowed_portals.iter().for_each(|var_index| {
                let _ = pm.get(&format!("var{}", var_index)).unwrap();
            });
        }

        // Return the subtraces, wrapped appropriately
        pm.subtraces
            .into_iter()
            .map(|subtrace| {
                subtrace
                    .into_iter()
                    .map(|e| TranscriptEntry::Rom(e))
                    .collect()
            })
            .collect()
    }
}
