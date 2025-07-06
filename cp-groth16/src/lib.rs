pub mod committer;
pub mod constraint_synthesizer;
pub mod data_structures;
pub mod generator;
pub mod prover;
pub mod verifier;

use ark_ec::pairing::Pairing;
pub use ark_groth16::r1cs_to_qap;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
pub use committer::CommitmentBuilder;
pub use constraint_synthesizer::*;
pub use data_structures::{CommitterKey, Proof, ProvingKey, VerifyingKey};

pub(crate) mod parallel;

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct CPGroth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: core::marker::PhantomData<(E, QAP)>,
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254 as E, Fr as F};
    use ark_ff::Field;
    use ark_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::FieldVar};
    use ark_relations::{
        ns,
        r1cs::{ConstraintSystemRef, SynthesisError},
    };
    use ark_std::{test_rng, vec::Vec, One, UniformRand};

    use crate::{
        committer::CommitmentBuilder,
        generator::generate_parameters,
        verifier::{prepare_verifying_key, verify_proof},
        MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
    };

    mod multi_stage_test {
        use super::*;
        /// A multistage circuit
        /// Stage 1. Witness a var and ensure it's 0
        /// Stage 2. Input a monic polynomial and prove knowledge of a root
        #[derive(Clone)]
        struct PolyEvalCircuit {
            // A polynomial that is committed in stage 0.
            pub polynomial: Vec<F>,

            // The variable corresponding to `polynomial` that is generated after stage 0.
            pub polynomial_var: Option<Vec<FpVar<F>>>,

            // The evaluation point for the polynomial.
            pub point: Option<F>,

            // The evaluation of `self.polynomial` at `self.root`.
            pub evaluation: Option<F>,
        }

        impl PolyEvalCircuit {
            fn new(polynomial: Vec<F>) -> Self {
                Self {
                    polynomial,
                    polynomial_var: None,
                    point: None,
                    evaluation: None,
                }
            }

            fn add_point(&mut self, point: F) {
                use ark_std::Zero;
                self.point = Some(point);
                self.evaluation = Some(
                    self.polynomial
                        .iter()
                        .enumerate()
                        .fold(F::zero(), |acc, (i, c)| acc + c * &point.pow(&[i as u64])),
                );
            }

            fn stage_0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                let polynomial_var = self
                    .polynomial
                    .iter()
                    .map(|c| FpVar::new_witness(ns!(cs, "coeff"), || Ok(c)))
                    .collect::<Result<Vec<_>, _>>()?;
                polynomial_var
                    .last()
                    .unwrap()
                    .enforce_equal(&FpVar::one())?;
                polynomial_var
                    .last()
                    .unwrap()
                    .enforce_equal(&FpVar::one())?;
                self.polynomial_var = Some(polynomial_var);

                Ok(())
            }

            fn stage_1(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                let point = FpVar::new_input(ns!(cs, "point"), || Ok(self.point.unwrap()))?;
                let evaluation =
                    FpVar::new_input(ns!(cs, "point"), || Ok(self.evaluation.unwrap()))?;
                let mut claimed_eval: FpVar<F> = FieldVar::zero();
                let mut cur_pow = FpVar::one();
                for coeff in self.polynomial_var.as_ref().unwrap() {
                    claimed_eval += coeff * &cur_pow;
                    cur_pow *= &point;
                }

                // Assert that it's a root
                claimed_eval.enforce_equal(&evaluation)?;
                Ok(())
            }
        }

        impl MultiStageConstraintSynthesizer<F> for PolyEvalCircuit {
            fn total_num_stages(&self) -> usize {
                2
            }

            fn generate_constraints(
                &mut self,
                stage: usize,
                cs: &mut MultiStageConstraintSystem<F>,
            ) -> Result<(), SynthesisError> {
                let out = match stage {
                    0 => cs.synthesize_with(|c| self.stage_0(c)),
                    1 => cs.synthesize_with(|c| self.stage_1(c)),
                    _ => panic!("unexpected stage stage {}", stage),
                };

                out
            }
        }

        // Do a Groth16 test that involves no commitment
        #[test]
        fn poly_commit_test() {
            let mut rng = test_rng();

            // Sample a random monic polynomial of the specified degree.
            let degree = 10;
            let mut polynomial = (0..degree).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
            polynomial.push(F::one());
            // Define the circuit we'll be using
            let circuit = PolyEvalCircuit::new(polynomial.clone());

            // Run the circuit and make sure it succeeds
            {
                let mut circuit = circuit.clone();
                let mut cs = MultiStageConstraintSystem::default();
                circuit.generate_constraints(0, &mut cs).unwrap();
                let point = F::rand(&mut rng);
                circuit.add_point(point);
                circuit.generate_constraints(1, &mut cs).unwrap();
                assert!(cs.is_satisfied().unwrap());
            }
            println!("Hello!");

            // Proof check
            //

            // Generate the proving key
            let pk = generate_parameters::<_, E, QAP>(circuit.clone(), &mut rng).unwrap();
            println!("Hello done with setup");

            let mut rng = test_rng();
            let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);
            let (comm, rand) = cb.commit(&mut rng).unwrap();
            let point = F::rand(&mut rng);
            cb.circuit.add_point(point);
            let inputs = [point, cb.circuit.evaluation.unwrap()];
            let proof = cb.prove(&[comm], &[rand], &mut rng).unwrap();

            // Verify
            let pvk = prepare_verifying_key(&pk.vk());
            assert!(verify_proof(&pvk, &proof, &inputs).unwrap());
        }
    }

    mod single_stage_test {
        use super::*;
        /// A multistage circuit
        /// Stage 1. Witness a var and ensure it's 0
        /// Stage 2. Input a monic polynomial and prove knowledge of a root
        #[derive(Clone)]
        struct PolyEvalCircuit {
            // A polynomial that is committed in stage 0.
            pub polynomial: Vec<F>,

            // The variable corresponding to `polynomial` that is generated after stage 0.
            pub polynomial_var: Option<Vec<FpVar<F>>>,

            // The evaluation point for the polynomial.
            pub point: Option<F>,

            // The evaluation of `self.polynomial` at `self.root`.
            pub evaluation: Option<F>,
        }

        impl PolyEvalCircuit {
            fn new(polynomial: Vec<F>) -> Self {
                Self {
                    polynomial,
                    polynomial_var: None,
                    point: None,
                    evaluation: None,
                }
            }

            fn add_point(&mut self, point: F) {
                use ark_std::Zero;
                self.point = Some(point);
                self.evaluation = Some(
                    self.polynomial
                        .iter()
                        .enumerate()
                        .fold(F::zero(), |acc, (i, c)| acc + c * &point.pow(&[i as u64])),
                );
            }

            fn stage_0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                let polynomial_var = self
                    .polynomial
                    .iter()
                    .map(|c| FpVar::new_witness(ns!(cs, "coeff"), || Ok(c)))
                    .collect::<Result<Vec<_>, _>>()?;
                polynomial_var
                    .last()
                    .unwrap()
                    .enforce_equal(&FpVar::one())?;
                self.polynomial_var = Some(polynomial_var);

                let point = FpVar::new_input(ns!(cs, "point"), || Ok(self.point.unwrap()))?;
                let evaluation =
                    FpVar::new_input(ns!(cs, "point"), || Ok(self.evaluation.unwrap()))?;
                let mut claimed_eval: FpVar<F> = FieldVar::zero();
                let mut cur_pow = FpVar::one();
                for coeff in self.polynomial_var.as_ref().unwrap() {
                    claimed_eval += coeff * &cur_pow;
                    cur_pow *= &point;
                }

                // Assert that it's a root
                claimed_eval.enforce_equal(&evaluation)?;

                Ok(())
            }
        }

        impl MultiStageConstraintSynthesizer<F> for PolyEvalCircuit {
            fn total_num_stages(&self) -> usize {
                1
            }

            fn generate_constraints(
                &mut self,
                stage: usize,
                cs: &mut MultiStageConstraintSystem<F>,
            ) -> Result<(), SynthesisError> {
                let out = match stage {
                    0 => cs.synthesize_with(|c| self.stage_0(c)),
                    _ => panic!("unexpected stage stage {}", stage),
                };

                out
            }
        }

        // Do a Groth16 test that involves no commitment
        #[test]
        fn poly_commit_test() {
            let mut rng = test_rng();

            // Sample a random monic polynomial of the specified degree.
            let degree = 10;
            let mut polynomial = (0..degree).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
            polynomial.push(F::one());
            // Define the circuit we'll be using
            let circuit = PolyEvalCircuit::new(polynomial.clone());

            // Run the circuit and make sure it succeeds
            {
                let mut circuit = circuit.clone();
                let mut cs = MultiStageConstraintSystem::default();
                let point = F::rand(&mut rng);
                circuit.add_point(point);
                circuit.generate_constraints(0, &mut cs).unwrap();
                assert!(cs.is_satisfied().unwrap());
            }
            println!("Hello!");

            //
            // Proof check
            //

            // Generate the proving key
            let pk = generate_parameters::<_, E, QAP>(circuit.clone(), &mut rng).unwrap();
            println!("Hello done with setup");

            let mut rng = test_rng();
            let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);
            let point = F::rand(&mut rng);
            cb.circuit.add_point(point);
            let inputs = [point, cb.circuit.evaluation.unwrap()];
            let proof = cb.prove(&[], &[], &mut rng).unwrap();

            // Verify
            let pvk = prepare_verifying_key(&pk.vk());
            assert!(verify_proof(&pvk, &proof, &inputs).unwrap());
        }
    }
}
