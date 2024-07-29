use rand::rngs::OsRng;
use bellman::{groth16, Circuit, ConstraintSystem, SynthesisError};
use blstrs::{Bls12, Scalar as Fr};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use ff::{Field, PrimeField};
use serde_json::json;
use solana_sdk::bs58::encode;

#[derive(Serialize, Deserialize)]
pub struct TransactionProof {
    pub transaction_hash: String,
    pub proof: String,
    pub input: Vec<String>,
}

pub struct BlockCircuit {
    pub block_hash: Option<Fr>,
    pub transaction_hashes: Vec<Option<Fr>>,
}

impl Circuit<Fr> for BlockCircuit {
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate the block hash
        let block_hash_var = cs.alloc(
            || "block hash",
            || self.block_hash.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Hash the transaction hashes
        let mut hasher = Sha256::new();
        for tx_hash in self.transaction_hashes.iter() {
            if let Some(hash) = tx_hash {
                hasher.update(hash.to_bytes_be());
            }
        }

        // Convert the final hash to a field element
        let result_hash = hasher.finalize();
        let mut result_hash_bytes = [0u8; 32];
        result_hash_bytes.copy_from_slice(&result_hash);
        let result_hash_fr = Fr::from_repr(result_hash_bytes).unwrap_or_else(|| Fr::ZERO);

        // Constrain the computed hash to be equal to the given block hash
        cs.enforce(
            || "block hash constraint",
            |lc| lc + block_hash_var,
            |lc| lc + CS::one(),
            |lc| lc + (result_hash_fr, CS::one()),
        );

        Ok(())
    }
}

pub fn generate_block_proof(block_hash: Fr, transaction_hashes: Vec<Fr>) -> (groth16::Proof<Bls12>, String, Vec<Fr>) {
    let circuit = BlockCircuit {
        block_hash: Some(block_hash),
        transaction_hashes: transaction_hashes.iter().map(|&x| Some(x)).collect(),
    };

    let mut rng = OsRng;
    let params = {
        let empty_circuit = BlockCircuit {
            block_hash: None,
            transaction_hashes: vec![None; transaction_hashes.len()],
        };
        groth16::generate_random_parameters::<Bls12, _, _>(empty_circuit, &mut rng).unwrap()
    };

    let proof = groth16::create_random_proof(circuit, &params, &mut rng).unwrap();
    let vk_bytes = serialize_vk(&params.vk);

    let proof_a_size = bincode::serialize(&proof.a).unwrap().len();
    let proof_b_size = bincode::serialize(&proof.b).unwrap().len();
    let proof_c_size = bincode::serialize(&proof.c).unwrap().len();
    println!("Proof 'a' size: {} bytes", proof_a_size);
    println!("Proof 'b' size: {} bytes", proof_b_size);
    println!("Proof 'c' size: {} bytes", proof_c_size);

    //let proof_bytes = bincode::serialize(&proof).unwrap();
    //println!("Total proof size: {} bytes", proof_bytes.len());

    //let input = vec![block_hash];

    (proof, vk_bytes, transaction_hashes)
}

pub(crate) fn str_to_fr(data: &str) -> Option<Fr> {
    // Convert string to bytes and then to Fr (handling errors)
    let hash = Sha256::digest(data.as_bytes());
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    println!("Converting hash to field element: {:?}", hash_bytes);
    Some(Fr::from_repr(hash_bytes).unwrap_or_else(|| Fr::ZERO))
}

pub fn save_proof_to_file(transaction_hash: &str, proof: &groth16::Proof<Bls12>, input: &[Fr]) {
    let proofs_dir = Path::new("proofs");
    if !proofs_dir.exists() {
        std::fs::create_dir(proofs_dir).expect("Unable to create proofs directory");
    }
    let file_name = proofs_dir.join(format!("proof_{}.json", transaction_hash));
    let mut file = File::create(&file_name).expect("Unable to create file");

    let input_data: Vec<String> = input.iter().map(|fr| format!("0x{}", to_hex_string(fr.to_bytes_be()))).collect();

    let json_data = json!({
        "input": input_data,
        "proof": {
            "a": [
                format!("0x{}", to_hex_string(proof.a.x().to_bytes_be())),
                format!("0x{}", to_hex_string(proof.a.y().to_bytes_be()))
            ],
            "b": [
                [
                    format!("0x{}", to_hex_string(proof.b.x().c0().to_bytes_be())),
                    format!("0x{}", to_hex_string(proof.b.x().c1().to_bytes_be()))
                ],
                [
                    format!("0x{}", to_hex_string(proof.b.y().c0().to_bytes_be())),
                    format!("0x{}", to_hex_string(proof.b.y().c1().to_bytes_be()))
                ]
            ],
            "c": [
                format!("0x{}", to_hex_string(proof.c.x().to_bytes_be())),
                format!("0x{}", to_hex_string(proof.c.y().to_bytes_be()))
            ]
        },
        "transaction_hash": transaction_hash
    });

    let json_string = serde_json::to_string_pretty(&json_data).expect("Unable to serialize proof");

    file.write_all(json_string.as_bytes()).expect("Unable to write data to file");

    println!("Saved proof to {:?}", file_name);
}

fn to_hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

pub fn save_vk_to_file(transaction_hash: &str, vk_string: &str) {
    let proofs_dir = Path::new("proofs");
    if !proofs_dir.exists() {
        std::fs::create_dir(proofs_dir).expect("Unable to create proofs directory");
    }
    let file_name = proofs_dir.join(format!("proof_{}_vk.json", transaction_hash));
    let mut file = File::create(&file_name).expect("Unable to create file");

    let json_data = serde_json::json!({
        "verifying_key": vk_string,
    });
    let json_string = serde_json::to_string_pretty(&json_data).expect("Unable to serialize vk");

    file.write_all(json_string.as_bytes()).expect("Unable to write data to file");

    println!("Saved verifying key to {:?}", file_name);
}

fn serialize_vk(vk: &groth16::VerifyingKey<Bls12>) -> String {
    let mut vk_bytes = vec![];
    vk.write(&mut vk_bytes).unwrap();
    encode(vk_bytes).into_string()
}
