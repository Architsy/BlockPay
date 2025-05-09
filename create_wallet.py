from solana.rpc.api import Client
from solders.keypair import Keypair
import base58
# Generate a new keypair
keypair = Keypair()
# Get the private key (secret key)
private_key_bytes = keypair.to_bytes()
private_key_base58 = base58.b58encode(private_key_bytes).decode()

# Get the public key (wallet address)
public_key = keypair.pubkey()

print("🔹 New Solana Wallet Created!")
print("📌 Wallet Address:", public_key)
print("🔑 Private Key (Keep Secure!):", private_key_base58)

