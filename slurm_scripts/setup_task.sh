#!/bin/bash

CIRC_TYPE=$1
KEYFILE_OUT=$2
NUM_SUBCIRCUITS=$3
NUM_SHA2_ITERS=$4
NUM_PORTALS=$5

module load openmpi

if [[ $CIRC_TYPE == "big-merkle" ]]; then
    /home/micro/horizontally-scalable-snarks-system/target/release/node setup-big-merkle \
        --num-subcircuits $NUM_SUBCIRCUITS \
        --num-sha2-iters $NUM_SHA2_ITERS \
        --num-portals $NUM_PORTALS \
        --key-out $KEYFILE_OUT
elif [[ $CIRC_TYPE == "vkd" ]]; then
	echo "NUM SUBCIRCS ==  $NUM_SUBCIRCUITS"
    /home/micro/horizontally-scalable-snarks-system/target/release/node setup-vkd \
        --num-subcircuits $NUM_SUBCIRCUITS \
        --key-out $KEYFILE_OUT
elif [[ $CIRC_TYPE == "vm" ]]; then
	echo "NUM SUBCIRCS ==  $NUM_SUBCIRCUITS"
    /home/micro/horizontally-scalable-snarks-system/target/release/node setup-vm \
        --num-subcircuits $NUM_SUBCIRCUITS \
	--num-cycles-per-subcircuit 1024 \
        --key-out $KEYFILE_OUT
else
    echo "Invalid circuit type $CIRC_TYPE"
    exit 1
fi
