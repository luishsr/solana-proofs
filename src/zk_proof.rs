use solana_sdk::transaction::Transaction;
use solana_transaction_status::{EncodedTransaction, UiConfirmedBlock, UiInstruction, UiMessage, UiParsedInstruction, UiTransactionEncoding};
use std::collections::HashMap;
use std::error::Error;
use rand::rngs::OsRng;
use bellman::{groth16, Circuit, ConstraintSystem, SynthesisError};
use blstrs::{Bls12, Scalar as Fr};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use ff::{Field, PrimeField};
use serde_json::{json, Value};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_response::RpcLeaderSchedule;
use solana_sdk::bs58;
use solana_sdk::bs58::encode;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::Signature;
use solana_transaction_status::EncodedConfirmedBlock;
use ed25519_dalek::{Signature as DalekSignature, PublicKey as DalekPublicKey, Verifier};
use solana_sdk::instruction::CompiledInstruction;
use solana_sdk::pubkey::Pubkey;

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

#[derive(Debug, Deserialize, Serialize)]
pub struct ParsedInstruction {
    pub program: String,
    pub parsed: VoteData,
    pub program_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteData {
    pub vote: VoteInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteInfo {
    pub slots: Vec<u64>,
    pub hash: String,
}

// Structure to hold the validator's public key and signature for the block
pub struct ValidatorSignature {
    pub validator_pubkey: String,
    pub signature: String,
}

// Structure to represent the current state of the blockchain
pub struct BlockState {
    pub state_hash: String,
}
// Function to validate the consensus proof
pub fn validate_consensus_proof(
    rpc_url: &str,
    slot: u64,
    expected_block_hash: &str,
    validator_signatures: &[ValidatorSignature],
) -> Result<bool, Box<dyn Error>> {
    // Create an RPC client to connect to the Solana blockchain
    let client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

    // Fetch the block information by slot
    let encoded_block: EncodedConfirmedBlock = client.get_block_with_encoding(slot, UiTransactionEncoding::Base64)?;

    // Verify the block hash
    if encoded_block.blockhash != expected_block_hash {
        println!("Block hash does not match the expected block hash.");
        return Ok(false);
    }

    // Get the leader schedule for the slot
    let leader_schedule = client.get_leader_schedule(Some(slot))?;

    // Map slot numbers to leaders
    let mut slot_to_leader = HashMap::new();
    if let Some(schedule) = leader_schedule {
        for (leader_pubkey, slots) in schedule {
            for &slot_index in slots.iter() {
                slot_to_leader.insert(slot_index as u64, leader_pubkey.clone());
            }
        }
    }

    // Verify each validator's signature
    for sig in validator_signatures {
        if let Some(validator_key) = slot_to_leader.get(&slot) {

            // Decode the validator's public key
            let pubkey_bytes = bs58::decode(validator_key).into_vec()?;
            if pubkey_bytes.len() != 32 {
                println!("Validator public key is not 32 bytes long: {}", validator_key);
                return Ok(false);
            }

            if validator_key == &sig.validator_pubkey {
                let signature_bytes = bs58::decode(&sig.signature).into_vec()?;
                let signature = DalekSignature::from_bytes(&signature_bytes)?;

                // Construct the message that was actually signed by the validator
                let message = construct_vote_message(&encoded_block)?;

                // Convert bytes to an ed25519_dalek::PublicKey
                let pubkey = DalekPublicKey::from_bytes(&pubkey_bytes)?;

                if !pubkey.verify(&message, &signature).is_ok() {
                    println!(
                        "Signature verification failed for validator: {}",
                        sig.validator_pubkey
                    );
                    return Ok(false);
                }
            } else {
                println!(
                    "Validator public key does not match the leader for the slot: {}",
                    sig.validator_pubkey
                );
                return Ok(false);
            }
        } else {
            println!("No leader found for the given slot: {}", slot);
            return Ok(false);
        }
    }

    println!("Consensus proof validated successfully.");
    Ok(true)
}

fn construct_vote_message(encoded_block: &EncodedConfirmedBlock) -> Result<Vec<u8>, Box<dyn Error>> {
    // Iterate over transactions to find vote transactions
    for transaction_with_meta in &encoded_block.transactions {
        if let EncodedTransaction::Binary(transaction_data_base64, _) = &transaction_with_meta.transaction {
            // Decode the Base64-encoded transaction data into bytes
            let transaction_data_bytes = base64::decode(transaction_data_base64)?;

            // Deserialize the transaction from the bytes
            let transaction: Transaction = bincode::deserialize(&transaction_data_bytes)?;

            // Check the instructions in the transaction
            for instruction in &transaction.message.instructions {
                // Use the CompiledInstruction directly
                if let Some(parsed_instruction) = parse_compiled_instruction(&transaction, instruction)? {
                    // Directly access the fields of the VoteData struct
                    let vote_info = &parsed_instruction.parsed.vote;
                    let mut message_bytes = Vec::new();

                    // Append slots to the message
                    for slot in &vote_info.slots {
                        message_bytes.extend_from_slice(&slot.to_le_bytes());
                    }
                    // Append blockhash
                    message_bytes.extend_from_slice(bs58::decode(&vote_info.hash).into_vec()?.as_slice());

                    return Ok(message_bytes);
                }
            }
        }
    }
    Err("No vote message found".into())
}

fn parse_compiled_instruction(
    transaction: &Transaction,
    instruction: &solana_sdk::instruction::CompiledInstruction,
) -> Result<Option<ParsedInstruction>, Box<dyn Error>> {
    let program_id_index = instruction.program_id_index as usize;
    if program_id_index >= transaction.message.account_keys.len() {
        return Err("Invalid program ID index".into());
    }

    let program_id = transaction.message.account_keys[program_id_index];
    let program_id_str = program_id.to_string();

    if program_id_str == "Vote111111111111111111111111111111111111111" {
        // Decode the instruction data as a vote instruction
        let vote_data = decode_vote_instruction(&instruction.data)?;

        // Create a ParsedInstruction with the decoded vote data
        let parsed_instruction = ParsedInstruction {
            program: "vote".to_string(),
            parsed: vote_data,
            program_id: program_id_str,
        };

        return Ok(Some(parsed_instruction));
    }

    Ok(None)
}

fn decode_vote_instruction(data: &[u8]) -> Result<VoteData, Box<dyn Error>> {
    println!("Decoding vote instruction data: {:?}", data);

    // Assuming first 8 bytes represent slot number and next 32 bytes represent a blockhash
    if data.len() < 40 {
        return Err("Vote instruction data is too short".into());
    }

    // Decode slot number
    let slot_bytes = &data[0..8];
    let slot = u64::from_le_bytes(slot_bytes.try_into()?);

    // Decode blockhash
    let blockhash_bytes = &data[8..40];
    let blockhash = bs58::encode(blockhash_bytes).into_string();

    // Construct the VoteData
    let vote_info = VoteInfo {
        slots: vec![slot],
        hash: blockhash,
    };

    let vote_data = VoteData {
        vote: vote_info,
    };

    Ok(vote_data)
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
