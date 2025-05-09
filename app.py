from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
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
import qrcode
import io
import base64
from PIL import Image
import json
from web3 import Web3
from eth_account import Account
import secrets

SCOPES = ["https://github.com/Architsy/BlockPay.git"]

# Initialize Web3
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR-PROJECT-ID'))  # Replace with your Infura project ID

# Predefined test wallets with initial balances
PREDEFINED_WALLETS = [
    {
        "name": "Default Wallet",
        "public_key": "C9UwhuhtCMkCJq3jAWg6RRar338oNZSLYwMfvrR1sxNR",
        "private_key": "5jARa2k5etKgpzjwtJmohpQryaq8osjiiLdL8ChusEJqcnSEzKss426KkgB4svxMLZ3AHMu35v6auuh2nzTqY6aZ",
        "balance": 100.0
    },
    {
        "name": "Test Wallet 2",
        "public_key": "BB7ismDWXSfkiB4VzzK8Rvtyz4WHj3ng2FysLQBeNXeg",
        "private_key": "63XV4YcgxYg1EHuh5Z4SCRYnXGv3WpuutuhUyM3238LHFJJV9rJNBFXNqUaC7ffm1oAvAQ1eVW3DgTSV6kazx3oW",
        "balance": 5.0
    },
    {
        "name": "Test Wallet 3",
        "public_key": "D6yNqctNvtNjAhAJWruGPJrxVvHBVGG7AasM9E9fGiW2",
        "private_key": "5rEL3883DbH5bCndacWdY5ktZis6EbSpzdvptdVsnoBf2UpxQqUJniXeikSxFyXKZdAetmXmjhd1QBZx4fXHBfjc",
        "balance": 7.5
    }
]

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key
client = Client("https://api.devnet.solana.com")

@app.before_request
def ensure_wallet():
    # If no wallet is loaded in session, preload the default wallet (with 100 SOL)
    if 'wallet' not in session:
        wallet = PREDEFINED_WALLETS[0]
        session['wallet'] = {
            'public_key': wallet['public_key'],
            'private_key': wallet['private_key'],
            'balance': wallet['balance']
        }

@app.route('/')
def index():
    return render_template('index.html', predefined_keys=PREDEFINED_WALLETS)

@app.route('/create_wallet', methods=['GET', 'POST'])
def create_wallet():
    if request.method == 'POST':
        try:
            keypair = Keypair()
            private_key = base58.b58encode(keypair.to_bytes()).decode()
            public_key = str(keypair.pubkey())

            # Store wallet info in session
            session['wallet'] = {
                'public_key': public_key,
                'private_key': private_key,
                'balance': 0.0
            }
            # Show both public and private key to the user
            flash('Wallet created successfully!', 'success')
            return render_template('create_wallet.html', public_key=public_key, private_key=private_key)
        except Exception as e:
            flash(f'Error creating wallet: {str(e)}', 'error')
    return render_template('create_wallet.html')

@app.route('/load_wallet', methods=['GET', 'POST'])
def load_wallet():
    if request.method == 'POST':
        public_key = request.form.get('public_key')
        private_key = request.form.get('private_key')
        try:
            keypair = Keypair.from_bytes(base58.b58decode(private_key))
            loaded_public_key = str(keypair.pubkey())
            if public_key and public_key != loaded_public_key:
                flash('Provided public key does not match the private key.', 'error')
                return render_template('load_wallet.html')
            # Store wallet info in session
            session['wallet'] = {
                'public_key': loaded_public_key,
                'private_key': private_key,
                'balance': 0.0
            }
            flash('Wallet loaded successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error loading wallet: {str(e)}', 'error')
    return render_template('load_wallet.html')

@app.route('/load_predefined_wallet/<int:index>')
def load_predefined_wallet(index):
    if 0 <= index < len(PREDEFINED_WALLETS):
        wallet = PREDEFINED_WALLETS[index]
        session['wallet'] = {
            'public_key': wallet['public_key'],
            'private_key': wallet['private_key'],
            'balance': wallet['balance']
        }
        flash(f'Predefined wallet loaded: {wallet["name"]}', 'success')
    else:
        flash('Invalid wallet index', 'error')
    return redirect(url_for('index'))

@app.route('/send_transaction', methods=['GET', 'POST'])
def send_transaction():
    if 'wallet' not in session:
        flash('Please load a wallet first', 'error')
        return redirect(url_for('index'))
    scanned_receiver = session.pop('scanned_receiver', None)
    scanned_amount = session.pop('scanned_amount', None)
    if request.method == 'POST':
        try:
            receiver = request.form.get('receiver')
            amount = float(request.form.get('amount'))
            if amount <= 0:
                flash('Amount must be greater than 0', 'error')
                return redirect(url_for('send_transaction'))
            if session['wallet']['balance'] < amount:
                flash('Insufficient balance', 'error')
                return redirect(url_for('send_transaction'))
            session['wallet']['balance'] -= amount
            for wallet in PREDEFINED_WALLETS:
                if wallet['public_key'] == receiver:
                    wallet['balance'] += amount
                    break
            flash(f'Transaction successful! Sent {amount} SOL to {receiver}', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Transaction failed: {str(e)}', 'error')
    return render_template('send_transaction.html', predefined_wallets=PREDEFINED_WALLETS, scanned_receiver=scanned_receiver, scanned_amount=scanned_amount)

@app.route('/check_balance')
def check_balance():
    if 'wallet' not in session:
        flash('Please load a wallet first', 'error')
        return redirect(url_for('index'))
    
    balance = session['wallet']['balance']
    flash(f'Current balance: {balance} SOL', 'success')
    return redirect(url_for('index'))

@app.route('/transaction_history')
def transaction_history():
    if 'wallet' not in session:
        flash("No wallet loaded.", "error")
        return redirect(url_for('index'))
    try:
        page = int(request.args.get('page', 1))
        per_page = 10
        pubkey = Pubkey.from_string(session['wallet']['public_key'])
        signatures_response = client.get_signatures_for_address(pubkey)
        transactions = []
        if signatures_response.value:
            for sig in signatures_response.value:
                transactions.append({
                    'signature': sig.signature,
                    'slot': sig.slot
                })
        total = len(transactions)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        paginated_transactions = transactions[start:end]
        return render_template('transaction_history.html',
                              transactions=paginated_transactions,
                              wallet=session['wallet']['public_key'],
                              page=page,
                              total_pages=total_pages)
    except Exception as e:
        flash(f"Failed to fetch transaction history: {e}", "error")
        return redirect(url_for('index'))

@app.route('/latest_block_info')
def latest_block_info():
    try:
        latest_slot = client.get_slot().value
        latest_block = client.get_block(latest_slot, encoding="jsonParsed", max_supported_transaction_version=0).value
        if latest_block:
            block_time = convert_time_zone(datetime.utcfromtimestamp(latest_block.block_time)) if latest_block.block_time else "Not available"
            block_info = (
                f"Block Height: {latest_slot}\n"
                f"Blockhash: {latest_block.blockhash}\n"
                f"Number of Transactions: {len(latest_block.transactions)}\n"
                f"Block Time: {block_time}"
            )
            flash(block_info, "success")
        else:
            flash("Failed to fetch block details.", "error")
    except Exception as e:
        flash(f"Failed to fetch block info: {e}", "error")
    return redirect(url_for('index'))

@app.route('/upload_to_drive', methods=['GET', 'POST'])
def upload_to_drive():
    if request.method == 'POST':
        file_path = request.form.get('file_path')
        folder_name = request.form.get('folder_name')
        if file_path and folder_name:
            try:
                drive_service = authenticate_google_drive()
                folder_id = create_drive_folder(drive_service, folder_name)
                file_metadata = {"name": os.path.basename(file_path), "parents": [folder_id]}
                media = MediaFileUpload(file_path, mimetype="application/octet-stream", resumable=True)
                file = drive_service.files().create(body=file_metadata, media_body=media, fields="id").execute()
                flash(f"File uploaded successfully! File ID: {file.get('id')}", "success")
            except Exception as e:
                flash(f"Failed to upload file: {e}", "error")
        return redirect(url_for('index'))
    return render_template('upload_to_drive.html')

@app.route('/validate_keypair', methods=['GET', 'POST'])
def validate_keypair():
    if request.method == 'POST':
        public_key = request.form.get('public_key')
        private_key = request.form.get('private_key')
        if public_key and private_key:
            try:
                valid = check_keypair(public_key, private_key)
                if valid:
                    flash("The keypair is valid!", "success")
                else:
                    flash("The keypair is invalid!", "error")
            except Exception as e:
                flash(f"Failed to validate keypair: {e}", "error")
        return redirect(url_for('index'))
    return render_template('validate_keypair.html')

@app.route('/connect_metamask', methods=['GET', 'POST'])
def connect_metamask():
    if request.method == 'POST':
        try:
            data = request.get_json()
            if data and 'address' in data:
                address = data['address']
                # Store wallet info in session
                session['metamask_wallet'] = {
                    'address': address,
                    'connected': True
                }
                return jsonify({
                    'success': True,
                    'message': 'Wallet connected successfully',
                    'address': address
                })
            return jsonify({
                'success': False,
                'message': 'Invalid wallet data'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            })
    return render_template('connect_metamask.html')

@app.route('/check_metamask_balance', methods=['POST'])
def check_metamask_balance():
    try:
        data = request.get_json()
        if data and 'address' in data:
            address = data['address']
            balance = w3.eth.get_balance(address)
            balance_in_eth = w3.from_wei(balance, 'ether')
            return jsonify({
                'success': True,
                'balance': str(balance_in_eth),
                'address': address
            })
        return jsonify({
            'success': False,
            'message': 'Invalid address'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/send_metamask_transaction', methods=['POST'])
def send_metamask_transaction():
    try:
        data = request.get_json()
        if data and all(k in data for k in ['from_address', 'to_address', 'amount']):
            from_address = data['from_address']
            to_address = data['to_address']
            amount = float(data['amount'])
            
            # Convert amount to Wei
            amount_in_wei = w3.to_wei(amount, 'ether')
            
            # Create transaction
            transaction = {
                'from': from_address,
                'to': to_address,
                'value': amount_in_wei,
                'gas': 21000,  # Standard gas limit for ETH transfers
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(from_address),
                'chainId': 1  # Mainnet
            }
            
            # Store transaction in session for reference
            session['last_transaction'] = {
                'from': from_address,
                'to': to_address,
                'amount': amount,
                'timestamp': datetime.now().isoformat()
            }
            
            return jsonify({
                'success': True,
                'message': 'Transaction created successfully',
                'transaction': transaction
            })
        return jsonify({
            'success': False,
            'message': 'Invalid transaction data'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/get_transaction_status', methods=['POST'])
def get_transaction_status():
    try:
        data = request.get_json()
        if data and 'tx_hash' in data:
            tx_hash = data['tx_hash']
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            if receipt:
                return jsonify({
                    'success': True,
                    'status': 'confirmed' if receipt['status'] == 1 else 'failed',
                    'block_number': receipt['blockNumber'],
                    'gas_used': receipt['gasUsed']
                })
            return jsonify({
                'success': True,
                'status': 'pending'
            })
        return jsonify({
            'success': False,
            'message': 'Invalid transaction hash'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/disconnect_metamask', methods=['POST'])
def disconnect_metamask():
    try:
        if 'metamask_wallet' in session:
            del session['metamask_wallet']
        return jsonify({
            'success': True,
            'message': 'Wallet disconnected successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/generate_qr', methods=['GET', 'POST'])
def generate_qr():
    if 'wallet' not in session:
        flash("No wallet loaded.", "error")
        return redirect(url_for('index'))
    if request.method == 'POST':
        amount = request.form.get('amount')
        public_key = session['wallet']['public_key']
        # Create QR code data
        qr_data = f"solana:{public_key}?amount={amount}" if amount else f"solana:{public_key}"
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        # Create QR code image
        img = qr.make_image(fill_color="#6648e1", back_color="#1a1a1a")
        # Convert to base64 for display
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return render_template('qr_code.html', qr_code=img_str, public_key=public_key, amount=amount)
    return render_template('generate_qr.html')

@app.route('/scan_qr', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'POST':
        qr_data = request.form.get('qr_data')
        if qr_data:
            try:
                # Parse QR data
                if qr_data.startswith('solana:'):
                    address = qr_data.split('?')[0].replace('solana:', '')
                    amount = qr_data.split('amount=')[1] if 'amount=' in qr_data else None
                    # Store scanned data in session for use on send_transaction page
                    session['scanned_receiver'] = address
                    session['scanned_amount'] = amount
                    return redirect(url_for('send_transaction'))
            except Exception as e:
                flash(f"Failed to parse QR: {e}", "error")
    return render_template('scan_qr.html')

def authenticate_google_drive():
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

def create_drive_folder(service, folder_name):
    query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    response = service.files().list(q=query, spaces="drive", fields="files(id)").execute()
    if response["files"]:
        return response["files"][0]["id"]
    folder_metadata = {"name": folder_name, "mimeType": "application/vnd.google-apps.folder"}
    folder = service.files().create(body=folder_metadata, fields="id").execute()
    return folder.get("id")

def check_keypair(public_key, private_key):
    pk = Keypair.from_bytes(base58.b58decode(private_key)).pubkey()
    return str(pk) == public_key

def convert_time_zone(time_utc):
    ist = pytz.timezone("Asia/Kolkata")
    time_ist = time_utc.replace(tzinfo=pytz.utc).astimezone(ist)
    return time_ist.strftime("%Y-%m-%d %H:%M:%S IST")

if __name__ == '__main__':
    app.run(debug=True)