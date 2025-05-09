from solders.keypair import Keypair
import load_keypair

# Example binary private key (replace with your actual bytes)
binary_private_key = b'b?\xbedR\xdf\xaa\xeb\xdb\xf0\x06\x85O\x0bJil\xf9\x0e@\x044pN\xe1*\xdbH\x08\xf8U\xb1'

# Convert binary private key to a Keypair object
keypair = Keypair.from_bytes(binary_private_key)

# Print the public key
print("Public Key:", keypair.pubkey())

# Print the private key in base58 format
print("Private Key (Base58):", load_keypair.private_key_from_keypair(keypair))
