use crate::vkd::sparse_tree::MerkleTreePath;
use crate::vkd::vkd::Leaf;
use crate::vkd::MerkleTreeConcreteParameters;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq)]
pub enum NodeAddress {
    PathRoot(PathRootAddress),
    LeafHash(LeafHashAddress),
    NullLeaf(NullLeafAddress),
    FinalRoot(FinalRootAddress),
    InitialRoot(InitialRootAddress),
    IntermediateRoot(IntermediateRootAddress),
}

/*
   types of nodes:
       "leaf hash"
       "path root"
       "null leaf"
       "initial leaf"
       "final root"
       "intermediate root"
*/
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct NodeAddressBytes {
    pub bytes: Vec<u8>,
    pub node_type: String,
}

impl NodeAddressBytes {
    pub fn node_address_to_bytes(node: NodeAddress) -> NodeAddressBytes {
        let mut bytes = Vec::new();
        let node_type: String;
        match node {
            NodeAddress::PathRoot(node) => {
                node.serialize_uncompressed(&mut bytes).unwrap();
                node_type = "path root".parse().unwrap();
            },
            NodeAddress::LeafHash(node) => {
                node.serialize_uncompressed(&mut bytes).unwrap();
                node_type = "leaf hash".parse().unwrap()
            },
            NodeAddress::NullLeaf(node) => {
                node.serialize_uncompressed(&mut bytes).unwrap();
                node_type = "null leaf".parse().unwrap();
            },
            NodeAddress::FinalRoot(node) => {
                node.serialize_uncompressed(&mut bytes).unwrap();
                node_type = "final root".parse().unwrap();
            },
            NodeAddress::InitialRoot(node) => {
                node.serialize_uncompressed(&mut bytes).unwrap();
                node_type = "initial leaf".parse().unwrap();
            },
            NodeAddress::IntermediateRoot(node) => {
                node.serialize_uncompressed(&mut bytes).unwrap();
                node_type = "intermediate root".parse().unwrap();
            },
        }
        NodeAddressBytes { bytes, node_type }
    }

    pub fn bytes_to_node_address(node_addr_bytes: NodeAddressBytes) -> NodeAddress {
        let node_type = node_addr_bytes.node_type;
        let bytes = node_addr_bytes.bytes;
        if node_type == "path root" {
            NodeAddress::PathRoot(
                PathRootAddress::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "leaf hash" {
            NodeAddress::LeafHash(
                LeafHashAddress::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "null leaf" {
            NodeAddress::NullLeaf(
                NullLeafAddress::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "final root" {
            NodeAddress::FinalRoot(
                FinalRootAddress::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "initial leaf" {
            NodeAddress::InitialRoot(
                InitialRootAddress::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "intermediate root" {
            NodeAddress::IntermediateRoot(
                IntermediateRootAddress::deserialize_uncompressed_unchecked(bytes.as_slice())
                    .unwrap(),
            )
        } else {
            panic!("wrong node address type");
        }
    }
}

impl NodeAddress {
    pub fn to_string(&self) -> String {
        match self {
            NodeAddress::PathRoot(address) => address.to_string(),
            NodeAddress::LeafHash(address) => address.to_string(),
            NodeAddress::NullLeaf(address) => address.to_string(),
            NodeAddress::InitialRoot(address) => address.to_string(),
            NodeAddress::FinalRoot(address) => address.to_string(),
            NodeAddress::IntermediateRoot(address) => address.to_string(),
        }
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct NullLeafAddress {}

impl NullLeafAddress {
    pub fn to_string(&self) -> String {
        "null leaf".to_string()
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct InitialRootAddress {}

impl InitialRootAddress {
    pub fn to_string(&self) -> String {
        "initial root".to_string()
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct FinalRootAddress {}

impl FinalRootAddress {
    pub fn to_string(&self) -> String {
        "final root".to_string()
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct PathRootAddress {
    // the index of the root
    pub(crate) path_id: usize,
    // the number of update that root is part of
    pub(crate) update_idx: usize,
}

impl PathRootAddress {
    pub fn to_string(&self) -> String {
        let i = self.path_id;
        let j = self.update_idx;
        format!("path root {i} {j}")
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct IntermediateRootAddress {
    pub(crate) indicator: usize,
    pub(crate) path_id: usize,
    pub(crate) update_idx: usize,
}

impl IntermediateRootAddress {
    pub fn to_string(&self) -> String {
        format!(
            "intermediate root {} {} {}",
            self.path_id, self.indicator, self.update_idx
        )
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct LeafHashAddress {
    pub(crate) leaf: Leaf,
}

impl LeafHashAddress {
    pub fn to_string(&self) -> String {
        format!("leaf hash {}", bytes_to_string(&self.leaf))
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct IndexAddress {
    // which part of indicator we are reading
    pub(crate) indicator: usize,
    // update number ==> so which leaf we are actually talking about
    pub(crate) leaf: Leaf,
}

impl IndexAddress {
    pub fn to_string(&self) -> String {
        let i = self.indicator;
        format!("index {i} {}", bytes_to_string(&self.leaf[0..32]))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrimitiveSubcircuit {
    EqualityPrimitive(EqualityPrimitive),
    GetIndexPrimitive(GetIndexPrimitive),
    ComputePathPrimitive(ComputePathPrimitive),
    HashLeafPrimitive(HashLeafPrimitive),
    PaddingPrimitive(PaddingPrimitive),
    WritePublicParameterPrimitive(WritePublicParameterPrimitive),
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct PrimitiveSubcircuitBytes {
    pub bytes: Vec<u8>,
    pub node_type: String,
}

impl PrimitiveSubcircuitBytes {
    pub fn primitive_subcircuit_to_bytes(
        primitive: PrimitiveSubcircuit,
    ) -> PrimitiveSubcircuitBytes {
        let mut bytes = Vec::new();
        match primitive {
            PrimitiveSubcircuit::EqualityPrimitive(p) => {
                p.serialize_uncompressed(&mut bytes).unwrap();
                PrimitiveSubcircuitBytes {
                    bytes,
                    node_type: "equality".parse().unwrap(),
                }
            },
            PrimitiveSubcircuit::GetIndexPrimitive(p) => {
                p.serialize_uncompressed(&mut bytes).unwrap();
                PrimitiveSubcircuitBytes {
                    bytes,
                    node_type: "get index".parse().unwrap(),
                }
            },
            PrimitiveSubcircuit::ComputePathPrimitive(p) => {
                p.serialize_uncompressed(&mut bytes).unwrap();
                PrimitiveSubcircuitBytes {
                    bytes,
                    node_type: "compute path".parse().unwrap(),
                }
            },
            PrimitiveSubcircuit::HashLeafPrimitive(p) => {
                p.serialize_uncompressed(&mut bytes).unwrap();
                PrimitiveSubcircuitBytes {
                    bytes,
                    node_type: "hash leaf".parse().unwrap(),
                }
            },
            PrimitiveSubcircuit::PaddingPrimitive(p) => {
                p.serialize_uncompressed(&mut bytes).unwrap();
                PrimitiveSubcircuitBytes {
                    bytes,
                    node_type: "padding".parse().unwrap(),
                }
            },
            PrimitiveSubcircuit::WritePublicParameterPrimitive(p) => {
                p.serialize_uncompressed(&mut bytes).unwrap();
                PrimitiveSubcircuitBytes {
                    bytes,
                    node_type: "write pp".parse().unwrap(),
                }
            },
        }
    }

    pub fn bytes_to_primitive_subcircuit(
        primitive_bytes: PrimitiveSubcircuitBytes,
    ) -> PrimitiveSubcircuit {
        let bytes = primitive_bytes.bytes;
        let node_type = primitive_bytes.node_type;
        if node_type == "equality" {
            PrimitiveSubcircuit::EqualityPrimitive(
                EqualityPrimitive::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "get index" {
            PrimitiveSubcircuit::GetIndexPrimitive(
                GetIndexPrimitive::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "compute path" {
            PrimitiveSubcircuit::ComputePathPrimitive(
                ComputePathPrimitive::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "hash leaf" {
            PrimitiveSubcircuit::HashLeafPrimitive(
                HashLeafPrimitive::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "padding" {
            PrimitiveSubcircuit::PaddingPrimitive(
                PaddingPrimitive::deserialize_uncompressed_unchecked(bytes.as_slice()).unwrap(),
            )
        } else if node_type == "write pp" {
            PrimitiveSubcircuit::WritePublicParameterPrimitive(
                WritePublicParameterPrimitive::deserialize_uncompressed_unchecked(bytes.as_slice())
                    .unwrap(),
            )
        } else {
            panic!("wrong primitive type")
        }
    }
}

impl PrimitiveSubcircuit {
    pub fn get_type(&self) -> &str {
        match self {
            PrimitiveSubcircuit::EqualityPrimitive(_) => "equality",
            PrimitiveSubcircuit::GetIndexPrimitive(_) => "get index",
            PrimitiveSubcircuit::ComputePathPrimitive(_) => "compute path",
            PrimitiveSubcircuit::HashLeafPrimitive(_) => "hash leaf",
            PrimitiveSubcircuit::PaddingPrimitive(_) => "padding",
            PrimitiveSubcircuit::WritePublicParameterPrimitive(_) => "write pp",
        }
    }

    pub fn get_update_idx(&self) -> i32 {
        match self {
            PrimitiveSubcircuit::EqualityPrimitive(eq) => eq.update_idx as i32,
            PrimitiveSubcircuit::ComputePathPrimitive(p) => p.update_idx as i32,
            _ => -1,
        }
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct EqualityPrimitive {
    pub(crate) update_idx: usize,
    pub(crate) addr1: NodeAddressBytes,
    pub(crate) addr2: NodeAddressBytes,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct GetIndexPrimitive {
    pub update_idx: usize,
    pub leaf: Leaf,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct ComputePathPrimitive {
    pub(crate) update_idx: usize,
    pub(crate) path_id: usize,
    pub(crate) indicator: usize,
    pub(crate) initial_value_addr: NodeAddressBytes,
    pub(crate) final_value_addr: NodeAddressBytes,
    pub(crate) index_addr: IndexAddress,
    pub(crate) path: MerkleTreePath<MerkleTreeConcreteParameters>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct HashLeafPrimitive {
    pub(crate) leaf: Leaf,
}

#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct PaddingPrimitive {}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct WritePublicParameterPrimitive {}

#[derive(Clone, Debug, PartialEq)]
pub struct SubCircuit {
    pub compound_primitive_vec: Vec<PrimitiveSubcircuit>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct SubcircuitBytes {
    pub bytes: Vec<PrimitiveSubcircuitBytes>,
}

impl SubcircuitBytes {
    pub fn subcircuit_to_bytes(subcircuit: &SubCircuit) -> SubcircuitBytes {
        let bytes: Vec<PrimitiveSubcircuitBytes> = subcircuit
            .compound_primitive_vec
            .clone()
            .iter()
            .map(|primitive| {
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(primitive.clone())
            })
            .collect();
        SubcircuitBytes { bytes }
    }

    pub fn bytes_to_subcircuit(subcircuit_bytes: SubcircuitBytes) -> SubCircuit {
        let compound_primitive_vec: Vec<PrimitiveSubcircuit> = subcircuit_bytes
            .bytes
            .clone()
            .iter()
            .map(|primitive| {
                PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(primitive.clone())
            })
            .collect();
        SubCircuit {
            compound_primitive_vec,
        }
    }
}

impl SubCircuit {
    pub fn get_type(&self) -> String {
        self.compound_primitive_vec
            .iter()
            .map(|item| item.get_type())
            .collect::<Vec<&str>>()
            .join(", ")
    }

    pub fn get_update_idx(&self) -> Vec<i32> {
        self.compound_primitive_vec
            .iter()
            .map(|item| item.get_update_idx())
            .collect::<Vec<i32>>()
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use crate::vkd::{
        default_leaf, ComputePathPrimitive, EqualityPrimitive, FinalRootAddress, GetIndexPrimitive,
        HashLeafPrimitive, IndexAddress, InitialRootAddress, IntermediateRootAddress,
        LeafHashAddress, MerkleTreePath, NodeAddress, NodeAddressBytes, NullLeafAddress,
        PaddingPrimitive, PathRootAddress, PrimitiveSubcircuit, PrimitiveSubcircuitBytes,
        SubCircuit, SubcircuitBytes, WritePublicParameterPrimitive,
    };
    use rand::Rng;

    #[test]
    fn test_serialization() {
        let mut rng = rand::thread_rng();
        let intermediate_root = NodeAddress::IntermediateRoot(IntermediateRootAddress {
            indicator: rng.gen::<usize>(),
            path_id: rng.gen::<usize>(),
            update_idx: rng.gen::<usize>(),
        });
        assert_eq!(
            intermediate_root.clone(),
            NodeAddressBytes::bytes_to_node_address(NodeAddressBytes::node_address_to_bytes(
                intermediate_root.clone()
            ))
        );

        let final_root = NodeAddress::FinalRoot(FinalRootAddress {});
        assert_eq!(
            final_root.clone(),
            NodeAddressBytes::bytes_to_node_address(NodeAddressBytes::node_address_to_bytes(
                final_root.clone()
            ))
        );

        let initial_root = NodeAddress::InitialRoot(InitialRootAddress {});
        assert_eq!(
            initial_root.clone(),
            NodeAddressBytes::bytes_to_node_address(NodeAddressBytes::node_address_to_bytes(
                initial_root.clone()
            ))
        );

        let null_leaf = NodeAddress::NullLeaf(NullLeafAddress {});
        assert_eq!(
            null_leaf.clone(),
            NodeAddressBytes::bytes_to_node_address(NodeAddressBytes::node_address_to_bytes(
                null_leaf.clone()
            ))
        );

        let leah_hash = NodeAddress::LeafHash(LeafHashAddress {
            leaf: default_leaf(),
        });
        assert_eq!(
            leah_hash.clone(),
            NodeAddressBytes::bytes_to_node_address(NodeAddressBytes::node_address_to_bytes(
                leah_hash.clone()
            ))
        );

        let path_root = NodeAddress::PathRoot(PathRootAddress {
            path_id: rng.gen::<usize>(),
            update_idx: rng.gen::<usize>(),
        });
        assert_eq!(
            path_root.clone(),
            NodeAddressBytes::bytes_to_node_address(NodeAddressBytes::node_address_to_bytes(
                path_root.clone()
            ))
        );

        let mut rng = rand::thread_rng();
        let equality = PrimitiveSubcircuit::EqualityPrimitive(EqualityPrimitive {
            update_idx: rng.gen::<usize>(),
            addr1: NodeAddressBytes::node_address_to_bytes(final_root.clone()),
            addr2: NodeAddressBytes::node_address_to_bytes(final_root.clone()),
        });
        assert_eq!(
            equality.clone(),
            PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(equality.clone())
            )
        );

        let padding = PrimitiveSubcircuit::PaddingPrimitive(PaddingPrimitive {});
        assert_eq!(
            padding.clone(),
            PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(padding.clone())
            )
        );

        let path = PrimitiveSubcircuit::ComputePathPrimitive(ComputePathPrimitive {
            update_idx: rng.gen::<usize>(),
            path_id: rng.gen::<usize>(),
            indicator: rng.gen::<usize>(),
            initial_value_addr: NodeAddressBytes::node_address_to_bytes(final_root.clone()),
            final_value_addr: NodeAddressBytes::node_address_to_bytes(final_root.clone()),
            index_addr: IndexAddress {
                indicator: rng.gen::<usize>(),
                leaf: default_leaf(),
            },
            path: MerkleTreePath::default(),
        });
        assert_eq!(
            path.clone(),
            PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(path.clone())
            )
        );

        let hash = PrimitiveSubcircuit::HashLeafPrimitive(HashLeafPrimitive {
            leaf: default_leaf(),
        });
        assert_eq!(
            hash.clone(),
            PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(hash.clone())
            )
        );

        let get_index = PrimitiveSubcircuit::GetIndexPrimitive(GetIndexPrimitive {
            update_idx: rng.gen::<usize>(),
            leaf: default_leaf(),
        });
        assert_eq!(
            get_index.clone(),
            PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(get_index.clone())
            )
        );

        let pp =
            PrimitiveSubcircuit::WritePublicParameterPrimitive(WritePublicParameterPrimitive {});
        assert_eq!(
            pp.clone(),
            PrimitiveSubcircuitBytes::bytes_to_primitive_subcircuit(
                PrimitiveSubcircuitBytes::primitive_subcircuit_to_bytes(pp.clone())
            )
        );

        let subcircuit = SubCircuit {
            compound_primitive_vec: vec![pp, get_index, hash, path, padding, equality],
        };
        assert_eq!(
            subcircuit.clone(),
            SubcircuitBytes::bytes_to_subcircuit(SubcircuitBytes::subcircuit_to_bytes(&subcircuit))
        );
    }
}
