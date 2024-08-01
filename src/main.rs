mod zk_proof;

use std::str::FromStr;
use solana_client::rpc_client::RpcClient;
use solana_sdk::clock::Slot;
use solana_sdk::signature::{Keypair, read_keypair_file, Signature, Signer};
use solana_sdk::transaction::Transaction;
use solana_sdk::{pubkey::Pubkey, system_instruction};
use solana_sdk::commitment_config::CommitmentConfig;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use solana_transaction_status::{EncodedTransaction, UiInstruction, UiMessage, UiParsedInstruction, UiParsedMessage, UiTransaction, UiTransactionEncoding};
use zk_proof::{generate_block_proof, str_to_fr, save_proof_to_file, save_vk_to_file, validate_consensus_proof, ValidatorSignature};

#[derive(Serialize, Deserialize)]
struct TransactionProof {
    transaction_hash: String,
    proof: String,
    input: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct BlockProof {
    slot: Slot,
    block_hash: String,
    transactions: Vec<TransactionProof>,
}

fn main() {
    // Define the RPC client
    let rpc_client = RpcClient::new("http://127.0.0.1:8899");

    // Generate a new keypair for the sender
    let sender_keypair = Keypair::new();

    // Airdrop 2 SOL to the new keypair
    let airdrop_amount = 2_000_000_000; // 2 SOL in lamports
    match rpc_client.request_airdrop(&sender_keypair.pubkey(), airdrop_amount) {
        Ok(signature) => {
            println!("Airdrop requested: {:?}", signature);
            // Wait for confirmation (polling the balance)
            loop {
                match rpc_client.get_balance(&sender_keypair.pubkey()) {
                    Ok(balance) => {
                        if balance >= airdrop_amount {
                            println!("Airdrop confirmed: {} lamports", balance);
                            break;
                        } else {
                            println!("Waiting for airdrop confirmation...");
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to get balance: {}", e);
                        return;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to request airdrop: {}", e);
            return;
        }
    };

    // Get the rent-exemption minimum balance for a new account
    let rent_exemption_amount = rpc_client.get_minimum_balance_for_rent_exemption(0).unwrap();


    // Get the recent blockhash
    let recent_blockhash = match rpc_client.get_latest_blockhash() {
        Ok(blockhash) => blockhash,
        Err(e) => {
            eprintln!("Failed to get recent blockhash: {}", e);
            return;
        }
    };

    // Define the recipient and the amount to send
    let recipient = Pubkey::new_unique();
    let amount = 1_000 + rent_exemption_amount; // 1 SOL in lamports + rent exemption

    // Create a transfer instruction
    let transfer_instruction = system_instruction::transfer(&sender_keypair.pubkey(), &recipient, amount);

    // Create the transaction
    let mut transaction = Transaction::new_with_payer(
        &[transfer_instruction],
        Some(&sender_keypair.pubkey()),
    );

    // Sign the transaction
    transaction.sign(&[&sender_keypair], recent_blockhash);

    // Log the transfer instruction details
    println!(
        "Transfer Instruction:\n\tFrom: {}\n\tTo: {}\n\tAmount: {}",
        sender_keypair.pubkey(),
        recipient,
        amount
    );

    // Send the transaction
    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(signature) => {
            println!("Transaction signature: {}", signature);
            // Get confirmation and receipt
            get_transaction_status(&rpc_client, &signature);
        }
        Err(e) => {
            eprintln!("Failed to send and confirm transaction: {}", e);
        }
    };
}
fn get_transaction_status(rpc_client: &RpcClient, signature: &Signature) {
    let max_retries = 10;
    let mut retries = 0;

    loop {
        if retries >= max_retries {
            println!("Transaction not confirmed within expected time.");
            break;
        }

        let result = rpc_client.get_signature_status_with_commitment(
            signature,
            CommitmentConfig::confirmed(),
        );

        match result {
            Ok(Some(Ok(_))) => {
                println!("Transaction confirmed");

                // Fetch necessary data for consensus proof validation
                let slot = rpc_client.get_slot().expect("Failed to get slot");

                // Fetch the block details at the given slot
                match rpc_client.get_block_with_encoding(slot, UiTransactionEncoding::JsonParsed) {
                    Ok(block) => {
                        let block_hash = block.blockhash.clone();

                        // Define the vector to collect validator signatures
                        let mut validator_signatures: Vec<ValidatorSignature> = Vec::new();

                        // Iterate over transactions to extract vote transactions
                        for transaction_with_meta in &block.transactions {
                            if let EncodedTransaction::Json(parsed_transaction) = &transaction_with_meta.transaction {
                                // Check if the transaction is a vote transaction
                                if is_vote_transaction(parsed_transaction) {
                                    // Extract the validator's public key and signature
                                    if let Some((validator_pubkey, signature)) = extract_validator_signature(parsed_transaction) {
                                        println!("Validator Public Key: {}", validator_pubkey);
                                        println!("Validator Signature: {}", signature);

                                        validator_signatures.push(ValidatorSignature {
                                            validator_pubkey: validator_pubkey.to_string(),
                                            signature,
                                        });
                                    }
                                }
                            }
                        }

                        println!("Total validator signatures processed: {}", validator_signatures.len());

                        // Call validate_consensus_proof
                        let rpc_url = "http://127.0.0.1:8899"; // Assuming this is your RPC URL
                        if let Err(err) = validate_consensus_proof(
                            rpc_url,
                            slot,
                            &block_hash,
                            &validator_signatures,
                        ) {
                            println!("Consensus proof validation failed: {:?}", err);
                        } else {
                            println!("Consensus proof validated successfully.");
                        }

                        // Generate zk-proof for the confirmed transaction
                        if let Some(tx_hash_fr) = str_to_fr(&signature.to_string()) {
                            let (proof, vk, input) = generate_block_proof(tx_hash_fr, vec![tx_hash_fr]);
                            println!("Generated zk-proof: {:?}", proof);

                            // Save the proof and vk to a file
                            save_proof_to_file(&signature.to_string(), &proof, &input);
                            save_vk_to_file(&signature.to_string(), &vk);
                        } else {
                            println!("Error converting transaction hash to field element");
                        }
                    }
                    Err(e) => {
                        println!("Failed to fetch block details for slot {}: {}", slot, e);
                    }
                }
                break;
            }
            Ok(Some(Err(err))) => {
                println!("Transaction failed with error: {:?}", err);
                break;
            }
            Ok(None) => println!("Transaction not found"),
            Err(err) => println!("Error fetching transaction status: {}", err),
        }

        retries += 1;
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn is_vote_transaction(parsed_transaction: &solana_transaction_status::UiTransaction) -> bool {
    if let UiMessage::Parsed(message) = &parsed_transaction.message {
        for instruction in &message.instructions {
            if let UiInstruction::Parsed(UiParsedInstruction::Parsed(parsed_instruction)) = instruction {
                if parsed_instruction.program_id == "Vote111111111111111111111111111111111111111" {
                    return true;
                }
            }
        }
    }
    false
}

fn extract_validator_signature(parsed_transaction: &solana_transaction_status::UiTransaction) -> Option<(Pubkey, String)> {
    // Extract the validator's public key and signature from the vote transaction
    if let UiMessage::Parsed(message) = &parsed_transaction.message {
        for (account, signature) in message.account_keys.iter().zip(parsed_transaction.signatures.iter()) {
            if account.signer {
                let pubkey = Pubkey::from_str(&account.pubkey).ok()?;
                return Some((pubkey, signature.clone()));
            }
        }
    }
    None
}