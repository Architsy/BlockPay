from solana.rpc.api import Client
from solders.pubkey import Pubkey  # Import Pubkey from solders
from datetime import datetime,UTC,timezone  # Import datetime for timestamp conversion
import load_keypair

# Connect to Solana mainnet (or devnet for testing)
solana_client = Client("https://api.devnet.solana.com")  # Use "https://api.devnet.solana.com" for devnet

# Wallet address (replace with the actual wallet address)
wallet_address = "BB7ismDWXSfkiB4VzzK8Rvtyz4WHj3ng2FysLQBeNXeg"

# Convert the wallet address to a Pubkey object
try:
    pubkey = Pubkey.from_string(wallet_address)
except ValueError:
    print("Invalid wallet address format.")
    exit()

# Fetch all transaction signatures for the wallet address
print(f"\nFetching transactions for wallet: {wallet_address}...")
signatures_response = solana_client.get_signatures_for_address(pubkey)

if signatures_response.value:
    signatures = [sig.signature for sig in signatures_response.value]
    print(f"Found {len(signatures)} transactions.")

    # Fetch and display details for each transaction
    for idx, signature in enumerate(signatures):
        print(f"\n=== Transaction {idx + 1} ===")
        print(f"Signature: {signature}")

        # Fetch transaction details
        transaction_response = solana_client.get_transaction(signature,max_supported_transaction_version=0)
        if transaction_response.value:
            tx_data = transaction_response.value
            print(f"Slot: {tx_data.slot}")
            #print(tx_data)
            if hasattr(tx_data, "block_time") and tx_data.block_time:
                tx_time = load_keypair.convert_time_zone(datetime.fromtimestamp(tx_data.block_time,UTC))
                print(f"Timestamp: {tx_time}")
            else:
                print("Timestamp: Not available")
            print(f"Fee: {tx_data.transaction.meta.fee} lamports")
            transfer_ammount=tx_data.transaction.meta.post_balances[1]-tx_data.transaction.meta.pre_balances[1]
            print(f"Transfered ammount: {transfer_ammount} lamports ({transfer_ammount/(10**9)} SOL)")
            print(f"Status: {'Success' if tx_data.transaction.meta.err is None else 'Failed'}")

            # Print Accounts Involved
            print("\nAccounts Involved:")
            for account_idx, account in enumerate(tx_data.transaction.transaction.message.account_keys):
                print(f"  Account {account_idx + 1}: {account}")

            # Print Logs
            print("\nLogs:")
            for log in tx_data.transaction.meta.log_messages:
                print(f"  {log}")
        else:
            print("Failed to fetch transaction details.")
else:
    print("No transactions found for this wallet address.")