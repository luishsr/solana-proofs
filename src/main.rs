mod zk_proof;

use solana_client::rpc_client::RpcClient;
use solana_sdk::clock::Slot;
use solana_sdk::signature::{Signer, Signature, read_keypair_file};
use solana_sdk::transaction::Transaction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use solana_sdk::commitment_config::CommitmentConfig;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use zk_proof::{generate_block_proof, str_to_fr, save_proof_to_file, save_vk_to_file};

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

    // Load the fee payer keypair from a file
    let fee_payer = read_keypair_file("fee_payer.json").expect("Failed to load keypair");

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
    let amount = 1_000; // 1 SOL in lamports

    // Create a transfer instruction
    let transfer_instruction = system_instruction::transfer(&fee_payer.pubkey(), &recipient, amount);

    // Create the transaction
    let mut transaction = Transaction::new_with_payer(
        &[transfer_instruction],
        Some(&fee_payer.pubkey()),
    );

    // Sign the transaction
    transaction.sign(&[&fee_payer], recent_blockhash);

    // Send the transaction
    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(signature) => {
            println!("Transaction signature: {}", signature);
            // Get confirmation and receipt
            get_transaction_status(&rpc_client, &signature);
        },
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

                // Generate zk-proof for the confirmed transaction
                if let Some(tx_hash_fr) = str_to_fr(&signature.to_string()) {
                    let (proof, vk, input) = generate_block_proof(tx_hash_fr, vec![tx_hash_fr]);
                    println!("Generated zk-proof: {}", proof);

                    // Save the proof and vk to a file
                    save_proof_to_file(&signature.to_string(), &proof, &input);
                    save_vk_to_file(&signature.to_string(), &vk);
                } else {
                    println!("Error converting transaction hash to field element");
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
