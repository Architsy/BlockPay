import pickle
from solders.keypair import Keypair
import base58

import pytz

def convert_time_zone(time_utc):
        ist = pytz.timezone('Asia/Kolkata')

        # Convert UTC to IST
        time_ist = time_utc.replace(tzinfo=pytz.utc).astimezone(ist)

        # Format the IST time
        time_ist_str = time_ist.strftime("%Y-%m-%d %H:%M:%S IST")
    
        return time_ist_str

def get_keypair(pubkey):

    file= open("private_keys/"+pubkey+".key","rb")

    keypair=pickle.load(file)

    return Keypair.from_bytes(keypair)

def keypair_from_private_key(private_key):
    private_key_bytes = base58.b58decode(private_key)

    # Check that the private key bytes are 64 bytes
    if len(private_key_bytes) == 64:
        # Reconstruct the Keypair from the private key bytes
        keypair = Keypair.from_bytes(private_key_bytes)
        return keypair
    else:
        raise(Exception("wrong key fomat"))
    
def private_key_from_keypair(keypair):

    private_key_bytes = keypair.to_bytes()
    private_key_base58 = base58.b58encode(private_key_bytes).decode()

    return private_key_base58

def check_keypair(public_key,private_key):
    pk=keypair_from_private_key(private_key).pubkey()

    return str(pk)==public_key

if __name__ == "__main__":
    print(check_keypair("C9UwhuhtCMkCJq3jAWg6RRar338oNZSLYwMfvrR1sxNR","5jARa2k5etKgpzjwtJmohpQryaq8osjiiLdL8ChusEJqcnSEzKss426KkgB4svxMLZ3AHMu35v6auuh2nzTqY6aZ"))