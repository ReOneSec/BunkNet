import argparse
import getpass
import json
import os
import sys
import hashlib
import binascii

import requests
from bip39 import bip39_generate, bip39_validate, bip39_mnemonic_to_seed
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

def get_keys_from_mnemonic(mnemonic: str) -> SigningKey:
    """Derives an ECDSA private key from a BIP39 mnemonic."""
    seed = bip39_mnemonic_to_seed(mnemonic)
    private_key_bytes = seed[:32]
    return SigningKey.from_string(private_key_bytes, curve=SECP256k1)

def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypts data using a password with AES-256."""
    salt = get_random_bytes(SALT_SIZE)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    # Prepend salt and IV for decryption
    return salt + cipher.iv + ciphertext

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """Decrypts data encrypted with AES-256."""
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE+AES.block_size]
    ciphertext = encrypted_data[SALT_SIZE+AES.block_size:]
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def save_wallet(mnemonic: str, password: str):
    """Encrypts and saves the mnemonic to the wallet file."""
    encrypted_mnemonic = encrypt_data(mnemonic.encode(), password)
    with open(WALLET_FILE, 'wb') as f:
        f.write(encrypted_mnemonic)
    print(f"✅ Wallet saved securely to {WALLET_FILE}")

def load_wallet(password: str) -> SigningKey:
    """Loads and decrypts the wallet, returning the key pair."""
    if not os.path.exists(WALLET_FILE):
        print(f"❌ Error: Wallet file '{WALLET_FILE}' not found. Please generate or import a wallet first.")
        sys.exit(1)
    with open(WALLET_FILE, 'rb') as f:
        encrypted_data = f.read()
    try:
        mnemonic = decrypt_data(encrypted_data, password).decode()
        return get_keys_from_mnemonic(mnemonic)
    except (ValueError, KeyError):
        print("❌ Error: Incorrect password or corrupted wallet file.")
        sys.exit(1)

# =============================================================================
# API INTERACTION
# =============================================================================

def get_address_info(address: str):
    """Fetches balance and history for an address."""
    try:
        response = requests.get(f"{BFF_API_URL}/address/{address}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to BunkNet API: {e}")
        sys.exit(1)

def send_transaction(key_pair: SigningKey, recipient: str, amount: float, fee: float):
    """Signs and sends a transaction."""
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
    """Generates a new wallet."""
    mnemonic = bip39_generate()
    print("✨ Your New Wallet Seed Phrase ✨")
    print("=" * 35)
    print(f"\n{mnemonic}\n")
    print("=" * 35)
    print("🛑 IMPORTANT: Write this phrase down and store it securely. It's the only way to recover your wallet.")
    password = getpass.getpass("Enter a strong password to encrypt this wallet: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        print("❌ Passwords do not match.")
        sys.exit(1)
    save_wallet(mnemonic, password)

def handle_import(args):
    """Imports a wallet from a seed phrase."""
    mnemonic = input("Enter your 12-word seed phrase: ").strip()
    if not bip39_validate(mnemonic):
        print("❌ Invalid seed phrase.")
        sys.exit(1)
    password = getpass.getpass("Enter a strong password to encrypt this wallet: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        print("❌ Passwords do not match.")
        sys.exit(1)
    save_wallet(mnemonic, password)
    
def handle_address(args):
    """Displays the wallet's public address."""
    password = getpass.getpass("Enter password to unlock wallet: ")
    key_pair = load_wallet(password)
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    print("\n🔑 Your BunkNet Public Address:")
    print(public_key)
    
def handle_balance(args):
    """Checks and displays the wallet's balance."""
    password = getpass.getpass("Enter password to unlock wallet: ")
    key_pair = load_wallet(password)
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    print(f"\n💰 Balance: {info.get('balance', 0):.4f} $BUNK")

def handle_history(args):
    """Displays transaction history."""
    password = getpass.getpass("Enter password to unlock wallet: ")
    key_pair = load_wallet(password)
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    transactions = info.get('transactions', [])
    print("\n📜 Transaction History:")
    if not transactions:
        print("No transactions found.")
        return
    for tx in reversed(transactions):
        direction = "OUT" if tx['sender'] == public_key else "IN "
        color_code = "\033[91m" if direction == "OUT" else "\033[92m" # Red for OUT, Green for IN
        print(f"{color_code}{direction}\033[0m | To/From: {tx['recipient' if direction == 'OUT' else tx['sender']][:15]}... | Amount: {tx['amount']:.2f} | Fee: {tx.get('fee', 0):.4f}")

def handle_send(args):
    """Handles sending tokens."""
    password = getpass.getpass("Enter password to unlock wallet: ")
    key_pair = load_wallet(password)
    print(f"Sending {args.amount} $BUNK to {args.to} with a fee of {args.fee} $BUNK...")
    send_transaction(key_pair, args.to, args.amount, args.fee)
    
# =============================================================================
# MAIN EXECUTION & ARGUMENT PARSING
# =============================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="BunkNet CLI Wallet - Manage your BunkNet assets.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # Generate command
    parser_generate = subparsers.add_parser('generate', help='Generate a new wallet and save it.')
    parser_generate.set_defaults(func=handle_generate)

    # Import command
    parser_import = subparsers.add_parser('import', help='Import a wallet from a seed phrase.')
    parser_import.set_defaults(func=handle_import)

    # Address command
    parser_address = subparsers.add_parser('address', help='Display your wallet public address.')
    parser_address.set_defaults(func=handle_address)

    # Balance command
    parser_balance = subparsers.add_parser('balance', help='Check your wallet balance.')
    parser_balance.set_defaults(func=handle_balance)
    
    # History command
    parser_history = subparsers.add_parser('history', help='View transaction history.')
    parser_history.set_defaults(func=handle_history)
    
    # Send command
    parser_send = subparsers.add_parser('send', help='Send $BUNK to another address.')
    parser_send.add_argument('--to', required=True, help='Recipient public address.')
    parser_send.add_argument('--amount', required=True, type=float, help='Amount of $BUNK to send.')
    parser_send.add_argument('--fee', default=0.01, type=float, help='Transaction fee (default: 0.01).')
    parser_send.set_defaults(func=handle_send)

    args = parser.parse_args()
    args.func(args)
