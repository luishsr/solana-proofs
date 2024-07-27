use solana_client::rpc_client::RpcClient;
use solana_sdk::signature::{Signer, Signature, read_keypair_file};
use solana_sdk::transaction::Transaction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use solana_sdk::commitment_config::CommitmentConfig;
use std::time::Duration;
mod zk_proof;
use zk_proof::{generate_block_proof, save_proof_to_file, save_vk_to_file, str_to_fr};

fn main() {
    let rpc_client = RpcClient::new("http://127.0.0.1:8899");

    let fee_payer = read_keypair_file("fee_payer.json").expect("Failed to load keypair");

    let recent_blockhash = match rpc_client.get_latest_blockhash() {
        Ok(blockhash) => blockhash,
        Err(e) => {
            eprintln!("Failed to get recent blockhash: {}", e);
            return;
        }
    };

    let recipient = Pubkey::new_unique();
    let amount = 1_000; // 1 SOL in lamports

    // Calculate the minimum balance needed for rent exemption
    let min_balance_for_rent_exemption = rpc_client.get_minimum_balance_for_rent_exemption(0).unwrap();

    // Create a transfer instruction to fund the recipient account with the minimum balance for rent exemption
    let fund_recipient_instruction = system_instruction::transfer(&fee_payer.pubkey(), &recipient, min_balance_for_rent_exemption);

    // Create a transfer instruction to send the desired amount to the recipient
    let transfer_instruction = system_instruction::transfer(&fee_payer.pubkey(), &recipient, amount);

    // Create the transaction with both instructions
    let mut transaction = Transaction::new_with_payer(
        &[fund_recipient_instruction, transfer_instruction],
        Some(&fee_payer.pubkey()),
    );

    transaction.sign(&[&fee_payer], recent_blockhash);

    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(signature) => {
            println!("Transaction signature: {}", signature);
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

                if let Some(tx_hash_fr) = str_to_fr(&signature.to_string()) {
                    let (proof, vk_bytes) = generate_block_proof(tx_hash_fr, vec![tx_hash_fr]);
                    println!("Generated zk-proof: {:?}", proof);

                    save_proof_to_file(&signature.to_string(), &proof);
                    save_vk_to_file(&vk_bytes);
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
