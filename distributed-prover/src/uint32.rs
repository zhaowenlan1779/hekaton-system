use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::{R1CSVar, ToBytesGadget};
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::borrow::Borrow;

#[derive(Clone)]
pub struct Unsigned32Var<F: PrimeField> {
    pub bits: Vec<Boolean<F>>,
}

#[derive(Clone, Eq, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Unsigned32 {
    pub bits: Vec<bool>,
}

impl<F: PrimeField> AllocVar<Unsigned32, F> for Unsigned32Var<F> {
    fn new_variable<T: Borrow<Unsigned32>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);
        let mut bits = Vec::new();
        for i in 0..entry.unwrap().bits.len() {
            let b = Boolean::new_variable(ns!(cs, "bit"), || entry.map(|e| e.bits[i]), mode)?;
            bits.push(b);
        }
        Ok(Unsigned32Var { bits })
    }
}

impl<F: PrimeField> R1CSVar<F> for Unsigned32Var<F> {
    type Value = Unsigned32;

    fn cs(&self) -> ConstraintSystemRef<F> {
        let cs = self.bits[0].cs();
        for i in 1..self.bits.len() {
            cs.clone().or(self.bits[i].cs());
        }
        cs.clone()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut bits = Vec::new();
        for b in &self.bits {
            bits.push(b.value()?);
        }
        Ok(Unsigned32 { bits })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for Unsigned32Var<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok(self.bits.chunks(8).map(UInt8::from_bits_le).collect())
    }
}

impl<F: PrimeField> Unsigned32Var<F> {
    pub fn new(cs: ConstraintSystemRef<F>) -> Self {
        Unsigned32Var {
            bits: vec![Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(); 32],
        }
    }

    pub fn to_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        Boolean::le_bits_to_fp_var(&self.bits)
    }

    pub fn increment_inplace(&mut self) {
        let mut carry = Boolean::new_witness(self.cs().clone(), || Ok(true)).unwrap();
        for index in 0..self.bits.len() {
            let prev_bit = self.bits[index].clone();
            self.bits[index] =
                Boolean::conditionally_select(&carry, &self.bits[index].not(), &self.bits[index])
                    .unwrap();
            carry = Boolean::conditionally_select(&prev_bit, &carry, &Boolean::FALSE).unwrap();
        }
    }

    pub fn is_greater_than(&self, other: &Self) -> Boolean<F> {
        let mut greater = Boolean::FALSE;
        let mut found_difference = Boolean::FALSE;
        for (a, b) in self.bits.iter().rev().zip(other.bits.iter().rev()) {
            // Use the Boolean<F> conditionally_select to simulate early exit logic
            let a_greater_b = a.and(&b.not()).unwrap();
            // Determine if this bit position has the first difference
            // XOR to find if there's a difference (0 if same, 1 if different
            let difference = a.xor(b).unwrap();
            // New difference found if not already found one and bits differ
            let found_a_new_difference = found_difference.not().and(&difference).unwrap();
            greater =
                Boolean::conditionally_select(&found_a_new_difference, &a_greater_b, &greater)
                    .unwrap();
            // Update found_difference to true if a new difference was found
            found_difference = found_difference.or(&found_a_new_difference).unwrap();
        }
        greater
    }

    pub fn enforce_equal(&self, other: &Self) {
        for i in 0..self.bits.len() {
            let _ = &self.bits[i].enforce_equal(&other.bits[i]);
        }
    }
}

impl<F: PrimeField> Unsigned32Var<F> {
    // Converts the U32 boolean vector into a native u32
    pub fn representation(&self) -> u32 {
        self.bits.iter().enumerate().fold(0, |acc, (index, bit)| {
            if bit.value().unwrap() {
                acc | (1 << index)
            } else {
                acc
            }
        })
    }
}

impl Unsigned32 {
    pub fn representation(&self) -> u32 {
        self.bits.iter().enumerate().fold(
            0,
            |acc, (index, bit)| {
                if *bit {
                    acc | (1 << index)
                } else {
                    acc
                }
            },
        )
    }

    // Converts the U32 boolean vector into a native field element
    pub fn as_field_elem<F: PrimeField>(&self) -> F {
        self.bits
            .iter()
            .enumerate()
            .fold(F::zero(), |acc, (index, &bit)| {
                if bit {
                    acc + F::from(1u64 << index)
                } else {
                    acc
                }
            })
    }

    // Increment the number by 1
    pub fn increment_inplace(&mut self) {
        let mut carry = true;
        for index in 0..self.bits.len() {
            if carry {
                carry = self.bits[index];
                // Flip the bit
                self.bits[index] = !self.bits[index];
            } else {
                break;
            }
        }
    }
}

impl Default for Unsigned32 {
    fn default() -> Self {
        Unsigned32 {
            bits: vec![false; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::uint32::{Unsigned32, Unsigned32Var};
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::random;

    #[test]
    fn test_u32_increment() {
        let mut u = Unsigned32Var::<Fr>::new(ConstraintSystem::<Fr>::new_ref());
        for i in 0u32..1000 {
            assert_eq!(u.representation(), i);
            u.increment_inplace();
        }
    }

    #[test]
    fn test_u32_comparison() {
        for _ in 0..10 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let mut num1 = Unsigned32Var::new(cs.clone());
            let mut num2 = Unsigned32Var::new(cs.clone());
            // Generate two random u64 numbers
            let mut a = random::<u16>();
            let mut b = random::<u16>();
            // Ensure a is not equal to b
            while a == b {
                b = random::<u16>();
            }
            // Swap if necessary to make sure a is greater than b
            if a < b {
                std::mem::swap(&mut a, &mut b);
            }
            assert!(
                a != b && a > b,
                "Post-condition failed: a must be greater than b and not equal"
            );
            for _ in 0..a {
                num1.increment_inplace();
            }
            for _ in 0..b {
                num2.increment_inplace();
            }
            assert!(num1.is_greater_than(&num2).value().unwrap());
            println!("{}", cs.num_constraints())
        }
    }

    #[test]
    fn test_u32_cmp() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        println!("{}", cs.num_constraints());
        let mut u1 = Unsigned32Var::<Fr>::new(cs.clone());
        println!("{}", cs.num_constraints());
        let u2 = Unsigned32Var::<Fr>::new(cs.clone());
        println!("{}", cs.num_constraints());
        u1.increment_inplace();
        println!("{}", cs.num_constraints());
        assert!(u1.is_greater_than(&u2).value().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_u32_new_variable() {
        let bits: Vec<bool> = (0..32).map(|_| random::<bool>()).collect();
        let mut u = Unsigned32 { bits };
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut v = Unsigned32Var::new_witness(cs.clone(), || Ok(u.clone())).unwrap();
        u.increment_inplace();
        v.increment_inplace();
        assert_eq!(u.representation(), v.representation());
    }
}
