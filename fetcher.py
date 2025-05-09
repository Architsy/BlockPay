from solana.rpc.api import Client
from datetime import datetime  # Import datetime for timestamp conversion
import pytz

def convert_time_zone(time_utc):
        ist = pytz.timezone('Asia/Kolkata')

        # Convert UTC to IST
        time_ist = time_utc.replace(tzinfo=pytz.utc).astimezone(ist)

        # Format the IST time
        time_ist_str = time_ist.strftime("%Y-%m-%d %H:%M:%S IST")
    
        return time_ist_str


devnet="https://api.devnet.solana.com"
og="https://api.mainnet-beta.solana.com"
# Connect to Solana mainnet
solana_client = Client(devnet)

# Fetch the latest block height (slot)
latest_slot = solana_client.get_slot().value  # Use .value instead of ["result"]

# Fetch recent blocks starting from the latest slot (last 100 slots)
block_range = solana_client.get_blocks(start_slot=latest_slot - 100, end_slot=latest_slot).value

print(block_range)

latest_block_height = block_range[-1] # Access the value attribute
print(f"Latest Block Height: {latest_block_height}")

# Fetch the latest block details with maxSupportedTransactionVersion
latest_block = solana_client.get_block(
    latest_block_height,
    encoding="jsonParsed",
    max_supported_transaction_version=0  # Add this parameter
)

if latest_block.value:  # Access the value attribute
    block_data = latest_block.value
    print("\n=== Block Details ===")
    print(f"Block Height: {latest_block_height}")
    if hasattr(block_data, "block_time") and block_data.block_time:
        block_time = convert_time_zone(datetime.utcfromtimestamp(block_data.block_time))

        print(f"Block Time: {block_time}")
    else:
        print("Block Time: Not available") 
    print(f"Blockhash: {block_data.blockhash}")
    print(f"Previous Blockhash: {block_data.previous_blockhash}")
    print(f"Parent Slot: {block_data.parent_slot}")
    print(f"Number of Transactions: {len(block_data.transactions)}")

    # Print Transactions
    print("\n=== Transactions ===")
    for idx, tx in enumerate(block_data.transactions):
        print(f"\nTransaction {idx + 1}:")
        print(f"  Signature: {tx.transaction.signatures[0]}")
        print(f"  Fee: {tx.meta.fee} lamports")
        print(f"  Status: {'Success' if tx.meta.err is None else 'Failed'}")

        # Print Transaction Timestamp (using the block's timestamp)
        if hasattr(block_data, "block_time") and block_data.block_time:
            tx_time = convert_time_zone(datetime.utcfromtimestamp(block_data.block_time))
            print(f"  Timestamp: {tx_time}")
        else:
            print("  Timestamp: Not available")

        # Print Accounts Involved in the Transaction
        print("\n  Accounts Involved:")
        for account_idx, account in enumerate(tx.transaction.message.account_keys):
            print(f"    Account {account_idx + 1}: {account}")

    # Print Rewards (if available)
    if hasattr(block_data, "rewards") and block_data.rewards:
        print("\n=== Rewards ===")
        for reward in block_data.rewards:
            print(f"  Pubkey: {reward.pubkey}")
            print(f"  Lamports: {reward.lamports}")
            print(f"  Reward Type: {reward.reward_type}")
            print(f"  Commission: {reward.commission}\n")

else:
    print("Failed to fetch block details.")