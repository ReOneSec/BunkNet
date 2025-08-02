import argparse
import getpass
import json
import os
import sys
import hashlib
import binascii

import requests
from mnemonic import Mnemonic
from ecdsa import SECP256k1, SigningKey
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Configuration ---
BFF_API_URL = "http://localhost:7000/api"
WALLET_FILE = "wallet.dat"
SALT_SIZE = 16
AES_KEY_LEN = 32
PBKDF2_ITERATIONS = 100000

# =============================================================================
# CRYPTOGRAPHY & WALLET HELPERS
# =============================================================================

mnemo = Mnemonic("english")

def get_keys_from_mnemonic(mnemonic: str) -> SigningKey:
    """Derives an ECDSA private key from a BIP39 mnemonic."""
    seed = Mnemonic.to_seed(mnemonic)
    private_key_bytes = seed[:32]
    return SigningKey.from_string(private_key_bytes, curve=SECP256k1)

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return salt + cipher.iv + ciphertext

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE+AES.block_size]
    ciphertext = encrypted_data[SALT_SIZE+AES.block_size:]
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def save_wallet(mnemonic: str, password: str):
    encrypted_mnemonic = encrypt_data(mnemonic.encode(), password)
    with open(WALLET_FILE, 'wb') as f: f.write(encrypted_mnemonic)
    print(f"✅ Wallet saved securely to {WALLET_FILE}")

# ## NEW ## - Helper function to reduce repeated code
def get_unlocked_wallet() -> SigningKey:
    """Prompts for password and returns the unlocked key pair."""
    password = getpass.getpass("Enter password to unlock wallet: ")
    if not os.path.exists(WALLET_FILE):
        print(f"❌ Error: Wallet file '{WALLET_FILE}' not found. Generate or import a wallet first.")
        sys.exit(1)
    with open(WALLET_FILE, 'rb') as f: encrypted_data = f.read()
    try:
        mnemonic = decrypt_data(encrypted_data, password).decode()
        return get_keys_from_mnemonic(mnemonic)
    except (ValueError, KeyError):
        print("❌ Error: Incorrect password or corrupted wallet file.")
        sys.exit(1)

def load_mnemonic(password: str) -> str:
    """Loads and decrypts the wallet, returning the mnemonic phrase."""
    if not os.path.exists(WALLET_FILE):
        print(f"❌ Error: Wallet file '{WALLET_FILE}' not found.")
        sys.exit(1)
    with open(WALLET_FILE, 'rb') as f: encrypted_data = f.read()
    try:
        return decrypt_data(encrypted_data, password).decode()
    except (ValueError, KeyError):
        print("❌ Error: Incorrect password or corrupted wallet file.")
        sys.exit(1)

# =============================================================================
# API INTERACTION
# =============================================================================
def get_address_info(address: str):
    try:
        response = requests.get(f"{BFF_API_URL}/address/{address}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to BunkNet API: {e}")
        sys.exit(1)

def send_transaction(key_pair: SigningKey, recipient: str, amount: float, fee: float):
    public_key_hex = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    tx_data = {'sender': public_key_hex, 'recipient': recipient, 'amount': amount, 'fee': fee}
    tx_data_str = json.dumps(tx_data, sort_keys=True)
    tx_hash = hashlib.sha256(tx_data_str.encode()).digest()
    signature = binascii.hexlify(key_pair.sign(tx_hash)).decode()
    payload = {**tx_data, 'public_key': public_key_hex, 'signature': signature}
    try:
        response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload)
        response.raise_for_status()
        print(f"✅ Transaction sent successfully!")
        print(response.json().get('message'))
    except requests.exceptions.RequestException as e:
        print(f"❌ Error sending transaction: {e.response.text if e.response else e}")
        sys.exit(1)

# =============================================================================
# CLI COMMAND HANDLERS
# =============================================================================

def handle_generate(args):
    mnemonic = mnemo.generate(strength=128)
    print("✨ Your New Wallet Seed Phrase ✨"); print("=" * 35); print(f"\n{mnemonic}\n"); print("=" * 35)
    print("🛑 IMPORTANT: Write this phrase down and store it securely. It's the only way to recover your wallet.")
    password = getpass.getpass("Enter a strong password to encrypt this wallet: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password: print("❌ Passwords do not match."); sys.exit(1)
    save_wallet(mnemonic, password)

def handle_import(args):
    mnemonic = input("Enter your 12-word seed phrase: ").strip()
    if not mnemo.check(mnemonic): print("❌ Invalid seed phrase."); sys.exit(1)
    password = getpass.getpass("Enter a strong password to encrypt this wallet: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password: print("❌ Passwords do not match."); sys.exit(1)
    save_wallet(mnemonic, password)
    
def handle_address(args):
    key_pair = get_unlocked_wallet() # ## MODIFIED ##
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    print("\n🔑 Your BunkNet Public Address:"); print(public_key)
    
def handle_balance(args):
    key_pair = get_unlocked_wallet() # ## MODIFIED ##
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    print(f"\n💰 Balance: {info.get('balance', 0):.4f} $BUNK")

# ## MODIFIED ## - This version is fixed to handle reward transactions correctly.
def handle_history(args):
    key_pair = get_unlocked_wallet()
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    transactions = info.get('transactions', [])
    
    print("\n📜 Transaction History:")
    if not transactions:
        print("No transactions found.")
        return
        
    for tx in reversed(transactions):
        if tx['sender'] == '0' and tx['recipient'] == public_key:
            # Handle mining reward transaction
            color_code = "\033[92m" # Green
            print(f"{color_code}IN \033[0m | From: Network Reward      | Amount: {tx['amount']:.2f}")
        else:
            # Handle normal P2P transaction
            direction = "OUT" if tx['sender'] == public_key else "IN "
            color_code = "\033[91m" if direction == "OUT" else "\033[92m"
            other_party = tx['recipient'] if direction == "OUT" else tx['sender']
            print(f"{color_code}{direction}\033[0m | To/From: {other_party[:15]:<15} | Amount: {tx['amount']:.2f} | Fee: {tx.get('fee', 0):.4f}")

# ## MODIFIED ## - This version adds a confirmation prompt for safety.
def handle_send(args):
    key_pair = get_unlocked_wallet()
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    balance = get_address_info(public_key).get('balance', 0)
    
    if (args.amount + args.fee) > balance:
        print(f"❌ Error: Insufficient funds. Your balance is {balance:.4f} $BUNK.")
        sys.exit(1)

    print("\n--- Transaction Summary ---")
    print(f"  Recipient: {args.to}")
    print(f"  Amount:    {args.amount:.4f} $BUNK")
    print(f"  Fee:       {args.fee:.4f} $BUNK")
    print("-" * 27)
    print(f"  Total:     {(args.amount + args.fee):.4f} $BUNK")
    print("-" * 27)
    
    confirm = input("Type 'yes' to confirm and send this transaction: ")
    if confirm.lower() != 'yes':
        print("Transaction cancelled.")
        sys.exit(0)
    
    print("\nSending transaction...")
    send_transaction(key_pair, args.to, args.amount, args.fee)

def handle_backup(args):
    password = getpass.getpass("Enter password to unlock wallet: ")
    print("\n" + "="*50 + "\n🛑 WARNING: SENSITIVE INFORMATION AHEAD 🛑");
    print("Anyone who sees this phrase can steal your funds.");
    print("Ensure you are in a private and secure location.\n" + "="*50 + "\n")
    mnemonic = load_mnemonic(password)
    print("🔑 Your private seed phrase is:\n"); print(f"{mnemonic}\n")

# =============================================================================
# MAIN EXECUTION & ARGUMENT PARSING
# =============================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="BunkNet CLI Wallet - Manage your BunkNet assets.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    parser_generate = subparsers.add_parser('generate', help='Generate a new wallet and save it.')
    parser_generate.set_defaults(func=handle_generate)
    parser_import = subparsers.add_parser('import', help='Import a wallet from a seed phrase.')
    parser_import.set_defaults(func=handle_import)
    parser_address = subparsers.add_parser('address', help='Display your wallet public address.')
    parser_address.set_defaults(func=handle_address)
    parser_balance = subparsers.add_parser('balance', help='Check your wallet balance.')
    parser_balance.set_defaults(func=handle_balance)
    parser_history = subparsers.add_parser('history', help='View transaction history.')
    parser_history.set_defaults(func=handle_history)
    parser_send = subparsers.add_parser('send', help='Send $BUNK to another address.')
    parser_send.add_argument('--to', required=True, help='Recipient public address.')
    parser_send.add_argument('--amount', required=True, type=float, help='Amount of $BUNK to send.')
    parser_send.add_argument('--fee', default=0.01, type=float, help='Transaction fee (default: 0.01).')
    parser_send.set_defaults(func=handle_send)
    parser_backup = subparsers.add_parser('backup', help='Show your secret seed phrase (for backup).')
    parser_backup.set_defaults(func=handle_backup)
    
    args = parser.parse_args()
    args.func(args)
    
