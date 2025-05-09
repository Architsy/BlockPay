from solana.rpc.api import Client
from solders.transaction import VersionedTransaction
from solders.system_program import TransferParams, transfer
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.message import MessageV0
import load_keypair

# Connect to Solana Devnet
solana_client = Client("https://api.devnet.solana.com")

# Load Keypair (Replace with your wallet's private key)
sender_p_key = "4hTcnfKV52rcC5tE9jqaoNEaHvexkpoer2PAKVEJpQLZeE52Zxoz4pnXV5BNBKi7dXUwQTUXxaKNYmPCETUYZFE1"
sender_keypair = load_keypair.keypair_from_private_key(sender_p_key)

# Receiver's Public Key
receiver_pubkey = Pubkey.from_string("BB7ismDWXSfkiB4VzzK8Rvtyz4WHj3ng2FysLQBeNXeg")

# Transfer amount (in lamports, 1 SOL = 1 billion lamports)
amount_in_lamports = 10**9  # 0.1 SOL

# Fetch a recent blockhash
latest_blockhash = solana_client.get_latest_blockhash().value.blockhash

# Create a transfer instruction
transfer_instruction = transfer(
    TransferParams(
        from_pubkey=sender_keypair.pubkey(),
        to_pubkey=receiver_pubkey,
        lamports=amount_in_lamports,
    )
)

# Create a message (Fixed: Added `recent_blockhash`)
message = MessageV0.try_compile(
    payer=sender_keypair.pubkey(),
    instructions=[transfer_instruction],
    address_lookup_table_accounts=[],
    recent_blockhash=latest_blockhash  # ✅ Fix: Added required blockhash
)

# Create a Versioned Transaction
transaction = VersionedTransaction(message, [sender_keypair])

# Send the transaction
response = solana_client.send_transaction(transaction)

# Output the transaction signature
print("Transaction Signature:", response.value)
