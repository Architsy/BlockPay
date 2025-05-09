# solana_suite_final.py
import argparse
import base58
import os
import pickle
import logging
from datetime import datetime, timezone
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction
from solders.message import MessageV0
import pytz

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class SolanaBlockchainFinal:
    def __init__(self, network="devnet"):
        self.network = network
        self.client = Client(self._get_rpc_url())
        self.keypair = None
        self.drive_service = None
        self._initialize_google_creds()

    def _initialize_google_creds(self):
        """Initialize Google credentials file."""
        creds_file = "credentials.json"
        if not os.path.exists(creds_file):
            logging.warning(f"{creds_file} not found. Creating a placeholder file.")
            with open(creds_file, "w") as f:
                f.write("{}")  # Placeholder for actual credentials

    def _get_rpc_url(self):
        """Return the RPC URL based on the network."""
        return "https://api.devnet.solana.com" if self.network == "devnet" else "https://api.mainnet-beta.solana.com"

    def create_wallet(self, backup=False):
        """Create a new wallet with optional Google Drive backup."""
        try:
            keypair = Keypair()
            private_key = base58.b58encode(keypair.to_bytes()).decode()
            pubkey = str(keypair.pubkey())
            logging.info(f"🔐 New Wallet Created:\nAddress: {pubkey}\nPrivate Key: {private_key}")
            if backup:
                self._backup_to_drive(private_key, pubkey)
            return keypair
        except Exception as e:
            logging.error(f"Error creating wallet: {e}")

    def _backup_to_drive(self, private_key, pubkey):
        """Backup keys to Google Drive."""
        try:
            if not self.drive_service:
                self._authenticate_drive()
            folder_id = self._create_drive_folder("SecureKeys")
            filename = f"{pubkey}.key"
            with open(filename, "w") as f:
                f.write(private_key)
            file_metadata = {"name": filename, "parents": [folder_id]}
            media = MediaFileUpload(filename, mimetype="text/plain")
            self.drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
            os.remove(filename)
            logging.info(f"✅ Backup completed to Google Drive: {filename}")
        except Exception as e:
            logging.error(f"Error during backup: {e}")

    def _authenticate_drive(self):
        """Authenticate user and return Google Drive service."""
        SCOPES = ["https://www.googleapis.com/auth/drive.file"]
        creds = None
        try:
            if os.path.exists("token.json"):
                creds = Credentials.from_authorized_user_file("token.json", SCOPES)
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                    creds = flow.run_local_server(port=0)
                with open("token.json", "w") as token_file:
                    token_file.write(creds.to_json())
            self.drive_service = build("drive", "v3", credentials=creds)
        except Exception as e:
            logging.error(f"Error authenticating Google Drive: {e}")

    def _create_drive_folder(self, folder_name):
        """Create a folder in Google Drive and return its folder ID."""
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
            response = self.drive_service.files().list(q=query).execute()
            if response["files"]:
                return response["files"][0]["id"]
            folder_metadata = {"name": folder_name, "mimeType": "application/vnd.google-apps.folder"}
            folder = self.drive_service.files().create(body=folder_metadata, fields="id").execute()
            return folder["id"]
        except Exception as e:
            logging.error(f"Error creating Google Drive folder: {e}")

    def load_wallet(self, private_key):
        """Load wallet from private key."""
        try:
            self.keypair = Keypair.from_bytes(base58.b58decode(private_key))
            logging.info(f"✅ Wallet loaded: {self.keypair.pubkey()}")
        except Exception as e:
            logging.error(f"❌ Error loading wallet: {e}")

    def get_balance(self, address=None):
        """Check account balance."""
        try:
            target = Pubkey.from_string(address) if address else self.keypair.pubkey()
            acc_info = self.client.get_account_info(target)
            if acc_info.value:
                return acc_info.value.lamports / 1_000_000_000
            return 0
        except Exception as e:
            logging.error(f"Error fetching balance: {e}")
            return 0

    def send_transaction(self, receiver, amount):
        """Send SOL transaction."""
        if not self.keypair:
            logging.error("❌ No wallet loaded")
            return
        try:
            transfer_instruction = transfer(TransferParams(
                from_pubkey=self.keypair.pubkey(),
                to_pubkey=Pubkey.from_string(receiver),
                lamports=int(amount * 1_000_000_000)
            ))
            message = MessageV0.try_compile(
                payer=self.keypair.pubkey(),
                instructions=[transfer_instruction],
                recent_blockhash=self.client.get_latest_blockhash().value.blockhash
            )
            transaction = VersionedTransaction(message, [self.keypair])
            response = self.client.send_transaction(transaction)
            logging.info(f"✅ Transaction sent: {response.value}")
        except Exception as e:
            logging.error(f"❌ Transaction failed: {e}")

    def get_transaction_history(self, address=None):
        """Get transaction history."""
        try:
            target = Pubkey.from_string(address) if address else self.keypair.pubkey()
            signatures_response = self.client.get_signatures_for_address(target)
            if signatures_response.value:
                return [{
                    "signature": str(sig.signature),
                    "slot": sig.slot,
                    "timestamp": self._convert_timestamp(sig.block_time) if sig.block_time else "N/A"
                } for sig in signatures_response.value]
            return []
        except Exception as e:
            logging.error(f"Error fetching transaction history: {e}")
            return []

    def _convert_timestamp(self, timestamp):
        """Convert UTC timestamp to IST."""
        try:
            utc_time = datetime.fromtimestamp(timestamp, timezone.utc)
            ist = pytz.timezone("Asia/Kolkata")
            return utc_time.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S IST")
        except Exception as e:
            logging.error(f"Error converting timestamp: {e}")
            return "N/A"

    def backup_file(self, file_path):
        """Backup arbitrary file to Google Drive."""
        try:
            self._authenticate_drive()
            folder_id = self._create_drive_folder("SecureBackups")
            file_metadata = {
                "name": os.path.basename(file_path),
                "parents": [folder_id]
            }
            media = MediaFileUpload(file_path, resumable=True)
            self.drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
            logging.info(f"✅ File backup completed: {file_path}")
        except Exception as e:
            logging.error(f"Error backing up file: {e}")

    def check_keypair(self, public_key, private_key):
        """Validate keypair from provided keys."""
        try:
            pk = self._keypair_from_private_key(private_key).pubkey()
            return str(pk) == public_key
        except Exception as e:
            logging.error(f"Keypair validation error: {e}")
            return False

    def _keypair_from_private_key(self, private_key):
        """Load keypair from private key string."""
        try:
            private_key_bytes = base58.b58decode(private_key)
            if len(private_key_bytes) == 64:
                return Keypair.from_bytes(private_key_bytes)
            raise ValueError("Invalid private key length")
        except Exception as e:
            logging.error(f"Error loading keypair from private key: {e}")
            raise

    def get_latest_block_info(self):
        """Fetch latest block details."""
        try:
            latest_slot = self.client.get_slot().value
            latest_block = self.client.get_block(
                latest_slot,
                encoding="jsonParsed",
                max_supported_transaction_version=0
            ).value
            if latest_block:
                block_time = self._convert_timestamp(latest_block.block_time) if latest_block.block_time else "Not available"
                return {
                    "block_height": latest_slot,
                    "block_time": block_time,
                    "blockhash": latest_block.blockhash,
                    "num_transactions": len(latest_block.transactions)
                }
            else:
                return {"error": "Failed to fetch block details."}
        except Exception as e:
            logging.error(f"Error fetching block info: {e}")
            return {"error": f"Error fetching block info: {e}"}

    def get_wallet_transactions(self, wallet_address):
        """Fetch all transactions for a specific wallet."""
        try:
            pubkey = Pubkey.from_string(wallet_address)
            signatures_response = self.client.get_signatures_for_address(pubkey)
            if signatures_response.value:
                transactions = []
                for sig in signatures_response.value:
                    tx_details = self.client.get_transaction(sig.signature, max_supported_transaction_version=0).value
                    if tx_details:
                        tx_time = self._convert_timestamp(tx_details.block_time) if tx_details.block_time else "Not available"
                        transactions.append({
                            "signature": sig.signature,
                            "slot": tx_details.slot,
                            "timestamp": tx_time,
                            "fee": tx_details.transaction.meta.fee,
                            "status": 'Success' if tx_details.transaction.meta.err is None else 'Failed'
                        })
                return transactions
            else:
                return {"message": "No transactions found for this wallet address."}
        except Exception as e:
            logging.error(f"Error fetching transactions: {e}")
            return {"error": f"Error fetching transactions: {e}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Solana Blockchain Suite - Final")
    parser.add_argument("--network", choices=["devnet", "mainnet"], default="devnet", help="Blockchain network")
    parser.add_argument("--create-wallet", action="store_true", help="Create new wallet")
    parser.add_argument("--backup", action="store_true", help="Enable Google Drive backup")
    parser.add_argument("--load-key", type=str, help="Load private key")
    parser.add_argument("--balance", type=str, nargs="?", const="", help="Check balance")
    parser.add_argument("--send", nargs=2, metavar=("RECEIVER", "AMOUNT"), help="Send SOL")
    parser.add_argument("--history", type=str, nargs="?", const="", help="Transaction history")
    parser.add_argument("--backup-file", type=str, help="Backup file to Google Drive")
    parser.add_argument("--validate-keypair", nargs=2, metavar=("PUBLIC_KEY", "PRIVATE_KEY"), help="Validate keypair")
    parser.add_argument("--latest-block", action="store_true", help="Get latest block info")
    parser.add_argument("--wallet-transactions", type=str, help="Get transactions for wallet")

    args = parser.parse_args()
    suite = SolanaBlockchainFinal(args.network)

    try:
        if args.create_wallet:
            suite.create_wallet(backup=args.backup)
        elif args.load_key:
            suite.load_wallet(args.load_key)
        elif args.balance is not None:
            address = args.balance if args.balance else None
            logging.info(f"Balance: {suite.get_balance(address)} SOL")
        elif args.send:
            suite.send_transaction(args.send[0], float(args.send[1]))
        elif args.history is not None:
            address = args.history if args.history else None
            logging.info("Transaction History: %s", suite.get_transaction_history(address))
        elif args.backup_file:
            suite.backup_file(args.backup_file)
        elif args.validate_keypair:
            public_key, private_key = args.validate_keypair
            if suite.check_keypair(public_key, private_key):
                logging.info("✅ Keypair is valid.")
            else:
                logging.info("❌ Keypair is invalid.")
        elif args.latest_block:
            logging.info("Latest Block Info: %s", suite.get_latest_block_info())
        elif args.wallet_transactions:
            logging.info("Wallet Transactions for %s: %s", args.wallet_transactions, suite.get_wallet_transactions(args.wallet_transactions))
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
