#![allow(warnings)]
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter};
use distributed_prover::{
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    vkd::{
        MerkleTreeParameters, VerifiableKeyDirectoryCircuit, VerifiableKeyDirectoryCircuitParams,
    },
    vm::VirtualMachine,
    CircuitWithPortals,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use mimalloc::MiMalloc;
use mpi_snark::{
    coordinator::CoordinatorState,
    data_structures::{
        ProvingKeys, Stage0Request, Stage0Response, Stage1Response, MERKLE_CIRCUIT_ID,
        VKD_CIRCUIT_ID, VM_CIRCUIT_ID,
    },
    deserialize_flattened_bytes, deserialize_from_packed_bytes, serialize_to_packed_vec,
    serialize_to_vec,
    worker::WorkerState,
    Packed, VkdMerkleParams,
};

use std::{
    fs::File,
    io::{Read, Write},
    num::NonZeroUsize,
    path::PathBuf,
};

#[cfg(feature = "parallel")]
use crossbeam::thread;
use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

macro_rules! start_timer {
    ($msg:expr) => {{
        use std::time::Instant;

        let msg = $msg();
        let start_info = "Start:";

        println!("{:8} {}", start_info, msg);
        (msg.to_string(), Instant::now())
    }};
}

macro_rules! end_timer {
    ($time:expr) => {{
        let time = $time.1;
        let final_time = time.elapsed();

        let end_info = "End:";
        let message = format!("{}", $time.0);

        println!("{:8} {} {}μs", end_info, message, final_time.as_micros());
    }};
}

#[derive(Parser)]
struct Args {
    /// Path to the coordinator key package
    #[clap(long, value_name = "DIR")]
    key_file: PathBuf,

    /// Max number of Groth16 proofs that should be performed concurrently. This is to limit memory
    /// usage.
    #[clap(long, value_name = "NUM")]
    num_concurrent_proofs: usize,
}

fn main() {
    #[cfg(feature = "parallel")]
    println!("Rayon num threads: {}", rayon::current_num_threads());

    let Args {
        key_file,
        num_concurrent_proofs,
    } = Args::parse();

    // Deserialize the proving keys
    let proving_keys = {
        let mut f = File::open(&key_file).expect(&format!("couldn't open file {:?}", key_file));
        ProvingKeys::deserialize_uncompressed_unchecked(&mut f).unwrap()
    };

    let circ_id = proving_keys.get_id_str();
    if circ_id == MERKLE_CIRCUIT_ID {
        work::<MerkleTreeCircuit>(proving_keys, num_concurrent_proofs);
    } else if circ_id == VKD_CIRCUIT_ID {
        work::<VerifiableKeyDirectoryCircuit>(proving_keys, num_concurrent_proofs);
    } else if circ_id == VM_CIRCUIT_ID {
        work::<VirtualMachine<Fr>>(proving_keys, num_concurrent_proofs);
    } else {
        panic!("unknown circuit ID {circ_id}")
    }
}

fn work<P: CircuitWithPortals<Fr>>(proving_keys: ProvingKeys, num_concurrent_proofs: usize) {
    let tmp_dir = mktemp::Temp::new_dir().unwrap().to_path_buf();
    std::fs::create_dir(&tmp_dir);
    let num_subcircuits = proving_keys.num_subcircuits();

    let very_start = start_timer!(|| format!("Beginning work"));

    let start = start_timer!(|| format!("Construct coordinator state"));
    let mut coordinator_state = CoordinatorState::<P>::new(&proving_keys);
    end_timer!(start);

    // Stage0 responses
    // Each commitment comes with a seed so we can reconstruct the commitment in stage1
    let (stage0_resps, stage0_seeds): (Vec<Stage0Response>, Vec<[u8; 32]>) = {
        // Stage0 requests
        let start = start_timer!(|| format!("Generating stage0 requests"));
        // TODO: Don't put all stage0 requests in memory at once
        let stage0_reqs = coordinator_state.stage_0();
        end_timer!(start);

        // Save stage0 requests to file. This is for two reasons:
        // 1) they're big
        // 2) they are a reference to coordinator_state.stage0_state, which is consumed by stage_1, but
        //    then later needed by WorkerState::stage_0 when reconstructing the committing state

        cfg_iter!(stage0_reqs).enumerate().for_each(|(i, req)| {
            let filename = format!("stage0_req_{i}.bin");
            let path = tmp_dir.join(filename);
            let mut file = File::create(path).unwrap();
            req.serialize_uncompressed(&mut file).unwrap();
        });

        cfg_into_iter!(stage0_reqs)
            .enumerate()
            .map(|(i, req)| {
                // Per-worker seed
                let mut seed: [u8; 32] = rand::thread_rng().gen();
                let mut rng = ChaCha12Rng::from_seed(seed);

                let start = start_timer!(|| format!("Processing stage0 request #{i}"));

                // Make a new state for each worker and compute the commimtent
                let resp =
                    WorkerState::<P>::new(num_subcircuits, &proving_keys).stage_0(&mut rng, &req);

                end_timer!(start);
                (resp, seed)
            })
            .unzip()
    };

    // Stage1 requests
    let start = start_timer!(|| format!("Processing stage0 responses"));
    let stage1_reqs = coordinator_state.stage_1(&stage0_resps);
    end_timer!(start);

    // Stage1 responses
    let chunk_size = num_subcircuits / num_concurrent_proofs;
    let stage1_resps = cfg_into_iter!(stage1_reqs, chunk_size)
        .enumerate()
        .zip(cfg_into_iter!(stage0_seeds, chunk_size))
        .map(|((i, req1), seed)| {
            // Per-worker seed
            let mut seed: [u8; 32] = rand::thread_rng().gen();
            let mut rng = ChaCha12Rng::from_seed(seed);

            // Load up the stage0 req
            let filename = format!("stage0_req_{i}.bin");
            let mut file = File::open(tmp_dir.join(filename)).unwrap();
            let req0 = Stage0Request::deserialize_uncompressed_unchecked(&mut file).unwrap();

            let mut state = WorkerState::new(num_subcircuits, &proving_keys);
            state.stage_0(&mut rng, &req0.to_ref());
            let start = start_timer!(|| format!("Processing stage1 request #{i}"));
            let resp = state.stage_1(&mut rng, &req1);
            end_timer!(start);
            resp
        })
        .collect::<Vec<_>>();

    let start = start_timer!(|| format!("Aggregating"));
    let _proof = coordinator_state.aggregate(&stage1_resps);
    end_timer!(start);

    end_timer!(very_start);

    std::fs::remove_dir_all(&tmp_dir);
}
