# Hekaton

This repo contains code for the [Hekaton](https://eprint.iacr.org/2024/1208) divide-and-aggregate zero-knowledge proof scheme.

## Code organization

The code is organized as follows:

- `cp-groth16` contains our implementation of Mirage, along with our interface for writing "staged" circuits that can be easily integrated with commit-and-prove SNARKs
- `distributed-prover` implements our DNA SNARK, and also implements the experiments described in the paper.
- `mpi-snark` implements the MPI binary  that runs the distributed prover on an MPI-compatible cluster.
- `slurm_scripts` contains various scripts required for running these experiments on our cluster. The most salient of these are the `setup_bench` script and the `run_single_bench` script, which respectively perform SRS generation and circuit proving.

## Caveats

- The code in this repo is not production-ready. It is the product of a small research team. Use with caution.
- We do not implement a standalone verifier for our proofs. The prover runs a verification routine [here](https://github.com/Pratyush/hekaton-system/blob/a1949383c446ad6581d60d79aba1cfb3acb04ff6/distributed-prover/src/aggregation.rs#L340), but we haven't exposed it as its own function.
- We do not implement an interface for specifying public inputs to circuits.

## Build instructions
This is a Rust library, and so can be compiled by using the `cargo` build tool.

To install `cargo` (and `rust`), follow the instructions here: rustup.rs.

This library is currently supported only on Linux; any relatively recent distribution should work.

A second dependency is OpenMPI; install this from your package manager of choice.

## Running benchmarks

The existing scripts for reproducing experiments are specialized for our university cluster. So you won't be able to run these to completion on your system.

To simply compile and run experiments *locally*, one can invoke the commands in the following scripts:
- `slurm_scripts/setup_task.sh` to perform SRS generation
- `slurm_scripts/my_task.sh` to invoke the distributed prover and benchmark its performance.

Specifically, the steps are as follows:

- First, switch to the `distributed_prover` folder.

- For setup for main scalability experiments:
```
cargo run --release setup-big-merkle \
    --num-subcircuits <num_subcircuits> \ # specifies number of subcircuits
    --num-sha2-iters <num_iters_of_sha2> \ # specifies subcircuit size
    --num-portals <num_shared_wires> \ # specifies number of shared wires
    --key-out <file_name> # specifies file to store the generated SRS
```

- For setup for verifiable key directory experiment:
```
cargo run --release setup-vkd \
    --num-subcircuits <num_subcircuits> \ # number of subcircuits
    --key-out <file_name> # specifies file to store the generated SRS
```

- For setup for VM experiment:
```
cargo run --release setup-vm \
    --num-subcircuits <num_subcircuits> \ # number of subcircuits (increasing this increases the size of the overall circuit)
    --num-cycles-per-subcircuit 1024 \
    --key-out <file_name> # specifies file to store the generated SRS
```

- Next, to run any of the corresponding experiments, simply invoke the following command:
```
cargo run --release work \
	--key-file <file_name> \ # the file produced in the steps above
	--num-workers <num_workers> \ # the number of MPI workers to use for this experiment.
```
