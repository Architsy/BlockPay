import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import base58
import os
import pickle
from datetime import datetime
import pytz
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

SCOPES = ["https://www.googleapis.com/auth/drive.file"]

# Predefined private keys
PREDEFINED_KEYS = [
    {
        "public_key": "C9UwhuhtCMkCJq3jAWg6RRar338oNZSLYwMfvrR1sxNR",
        "private_key": "5jARa2k5etKgpzjwtJmohpQryaq8osjiiLdL8ChusEJqcnSEzKss426KkgB4svxMLZ3AHMu35v6auuh2nzTqY6aZ"
    },
    {
        "public_key": "BB7ismDWXSfkiB4VzzK8Rvtyz4WHj3ng2FysLQBeNXeg",
        "private_key": "63XV4YcgxYg1EHuh5Z4SCRYnXGv3WpuutuhUyM3238LHFJJV9rJNBFXNqUaC7ffm1oAvAQ1eVW3DgTSV6kazx3oW"
    },
    {
        "public_key": "D6yNqctNvtNjAhAJWruGPJrxVvHBVGG7AasM9E9fGiW2",
        "private_key": "5rEL3883DbH5bCndacWdY5ktZis6EbSpzdvptdVsnoBf2UpxQqUJniXeikSxFyXKZdAetmXmjhd1QBZx4fXHBfjc"
    },
    {
        "public_key": "7Dorr4rB4Rgjc5ZXtY6WjXfcrpUenNmkkKsdWuZJDCr9",
        "private_key": "Te8Qk3hNuGE7PSGRLw4fELeGFwrcL4R9NhcYCHTRzSkQfdhLr6BBUaehjr16zXTDq3LCZuzkPQxFBpZu5pfWkbP"
    },
    {
        "public_key": "7E3KqCVHss6X2vKGeHjNeuwyvewjbD49zVoiugMJbCt1",
        "private_key": "4hTcnfKV52rcC5tE9jqaoNEaHvexkpoer2PAKVEJpQLZeE52Zxoz4pnXV5BNBKi7dXUwQTUXxaKNYmPCETUYZFE1"
    }
]

class SolanaBlockchainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Solana Blockchain Suite")
        self.root.geometry("900x700")
        self.root.configure(bg="#2c3e50")
        self.client = Client("https://api.devnet.solana.com")
        self.keypair = None

        # Title Label
        title_label = tk.Label(
            root, text="Solana Blockchain Suite", font=("Helvetica", 24, "bold"), bg="#2c3e50", fg="#ecf0f1"
        )
        title_label.pack(pady=20)

        # Create a frame for buttons
        button_frame = tk.Frame(root, bg="#2c3e50")
        button_frame.pack(pady=10)

        # Add buttons with styles
        self.create_button(button_frame, "Create Wallet", self.create_wallet)
        self.create_button(button_frame, "Load Wallet", self.load_wallet)
        self.create_button(button_frame, "Check Balance", self.check_balance)
        self.create_button(button_frame, "Send Transaction", self.send_transaction)
        self.create_button(button_frame, "Transaction History", self.transaction_history)
        self.create_button(button_frame, "Latest Block Info", self.latest_block_info)
        self.create_button(button_frame, "Upload to Google Drive", self.upload_to_drive)
        self.create_button(button_frame, "Validate Keypair", self.validate_keypair)

        # Predefined Keys Section
        predefined_keys_frame = tk.Frame(root, bg="#34495e", padx=10, pady=10)
        predefined_keys_frame.pack(pady=20, fill=tk.X)
        tk.Label(predefined_keys_frame, text="Predefined Wallets", font=("Helvetica", 16, "bold"), bg="#34495e", fg="#ecf0f1").pack()
        for key in PREDEFINED_KEYS:
            tk.Button(
                predefined_keys_frame,
                text=f"Public Key: {key['public_key']}",
                command=lambda k=key: self.load_predefined_wallet(k),
                bg="#1abc9c", fg="#ecf0f1", font=("Helvetica", 12), relief=tk.RAISED
            ).pack(pady=5, fill=tk.X)

        # Footer
        footer_label = tk.Label(
            root, text="Powered by Solana Blockchain", font=("Helvetica", 10), bg="#2c3e50", fg="#bdc3c7"
        )
        footer_label.pack(side=tk.BOTTOM, pady=10)

    def create_button(self, parent, text, command):
        """Helper function to create styled buttons."""
        button = ttk.Button(parent, text=text, command=command)
        button.pack(pady=5, ipadx=10, ipady=5, fill=tk.X)

    def create_wallet(self):
        """Create a new wallet."""
        self.keypair = Keypair()
        private_key = base58.b58encode(self.keypair.to_bytes()).decode()
        pubkey = str(self.keypair.pubkey())
        messagebox.showinfo("New Wallet", f"Address: {pubkey}\nPrivate Key: {private_key}")

    def load_wallet(self):
        """Load wallet from private key."""
        private_key = simpledialog.askstring("Load Wallet", "Enter your private key:")
        if private_key:
            try:
                self.keypair = Keypair.from_bytes(base58.b58decode(private_key))
                messagebox.showinfo("Wallet Loaded", f"Wallet loaded successfully!\nAddress: {self.keypair.pubkey()}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load wallet: {e}")

    def load_predefined_wallet(self, key):
        """Load a predefined wallet."""
        try:
            self.keypair = Keypair.from_bytes(base58.b58decode(key["private_key"]))
            messagebox.showinfo("Wallet Loaded", f"Predefined Wallet Loaded!\nAddress: {key['public_key']}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load predefined wallet: {e}")

    def check_balance(self):
        """Check the balance of the loaded wallet."""
        if not self.keypair:
            messagebox.showerror("Error", "No wallet loaded.")
            return
        try:
            pubkey = self.keypair.pubkey()
            balance = self.client.get_balance(pubkey).value / 1_000_000_000
            messagebox.showinfo("Balance", f"Balance: {balance} SOL")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch balance: {e}")

    def send_transaction(self):
        """Send a transaction."""
        if not self.keypair:
            messagebox.showerror("Error", "No wallet loaded.")
            return
        receiver = simpledialog.askstring("Send Transaction", "Enter receiver's address:")
        amount = simpledialog.askfloat("Send Transaction", "Enter amount to send (SOL):")
        if receiver and amount:
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
                messagebox.showinfo("Transaction Sent", f"Transaction sent successfully!\nSignature: {response.value}")
            except Exception as e:
                messagebox.showerror("Error", f"Transaction failed: {e}")

    def transaction_history(self):
        """Get transaction history."""
        if not self.keypair:
            messagebox.showerror("Error", "No wallet loaded.")
            return
        try:
            pubkey = self.keypair.pubkey()
            signatures_response = self.client.get_signatures_for_address(pubkey)
            if signatures_response.value:
                history = "\n".join([f"Signature: {sig.signature}, Slot: {sig.slot}" for sig in signatures_response.value])
                messagebox.showinfo("Transaction History", history)
            else:
                messagebox.showinfo("Transaction History", "No transactions found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch transaction history: {e}")

    def latest_block_info(self):
        """Get the latest block info."""
        try:
            latest_slot = self.client.get_slot().value
            latest_block = self.client.get_block(latest_slot, encoding="jsonParsed").value
            if latest_block:
                block_time = self.convert_time_zone(datetime.utcfromtimestamp(latest_block.block_time)) if latest_block.block_time else "Not available"
                block_info = (
                    f"Block Height: {latest_slot}\n"
                    f"Blockhash: {latest_block.blockhash}\n"
                    f"Number of Transactions: {len(latest_block.transactions)}\n"
                    f"Block Time: {block_time}"
                )
                messagebox.showinfo("Latest Block Info", block_info)
            else:
                messagebox.showinfo("Latest Block Info", "Failed to fetch block details.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch block info: {e}")

    def upload_to_drive(self):
        """Upload a file to Google Drive."""
        file_path = simpledialog.askstring("Upload File", "Enter the file path to upload:")
        folder_name = simpledialog.askstring("Upload File", "Enter the Google Drive folder name:")
        if file_path and folder_name:
            try:
                drive_service = self.authenticate_google_drive()
                folder_id = self.create_drive_folder(drive_service, folder_name)
                file_metadata = {"name": os.path.basename(file_path), "parents": [folder_id]}
                media = MediaFileUpload(file_path, mimetype="application/octet-stream", resumable=True)
                file = drive_service.files().create(body=file_metadata, media_body=media, fields="id").execute()
                messagebox.showinfo("Upload Successful", f"File uploaded successfully! File ID: {file.get('id')}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload file: {e}")

    def validate_keypair(self):
        """Validate a keypair."""
        public_key = simpledialog.askstring("Validate Keypair", "Enter the public key:")
        private_key = simpledialog.askstring("Validate Keypair", "Enter the private key:")
        if public_key and private_key:
            try:
                valid = self.check_keypair(public_key, private_key)
                if valid:
                    messagebox.showinfo("Validation Successful", "The keypair is valid!")
                else:
                    messagebox.showerror("Validation Failed", "The keypair is invalid!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to validate keypair: {e}")

    def authenticate_google_drive(self):
        """Authenticate user and return Google Drive service."""
        creds = None
        token_path = "token.json"
        if os.path.exists(token_path):
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
            with open(token_path, "w") as token_file:
                token_file.write(creds.to_json())
        return build("drive", "v3", credentials=creds)

    def create_drive_folder(self, service, folder_name):
        """Create a folder in Google Drive."""
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        response = service.files().list(q=query, spaces="drive", fields="files(id)").execute()
        if response["files"]:
            return response["files"][0]["id"]
        folder_metadata = {"name": folder_name, "mimeType": "application/vnd.google-apps.folder"}
        folder = service.files().create(body=folder_metadata, fields="id").execute()
        return folder.get("id")

    def check_keypair(self, public_key, private_key):
        """Validate a keypair."""
        pk = Keypair.from_bytes(base58.b58decode(private_key)).pubkey()
        return str(pk) == public_key

    def convert_time_zone(self, time_utc):
        """Convert UTC to IST."""
        ist = pytz.timezone("Asia/Kolkata")
        time_ist = time_utc.replace(tzinfo=pytz.utc).astimezone(ist)
        return time_ist.strftime("%Y-%m-%d %H:%M:%S IST")

if __name__ == "__main__":
    root = tk.Tk()
    app = SolanaBlockchainApp(root)

    # Apply ttk theme for better aesthetics
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", font=("Helvetica", 12), padding=5)
    style.configure("TLabel", font=("Helvetica", 12))

    root.mainloop()