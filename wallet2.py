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

# ANSI Color Codes for better UI
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# =============================================================================
# CRYPTOGRAPHY & WALLET HELPERS
# =============================================================================

mnemo = Mnemonic("english")

def get_keys_from_mnemonic(mnemonic: str) -> SigningKey:
    # This block is correctly indented
    seed = Mnemonic.to_seed(mnemonic)
    private_key_bytes = seed[:32]
    return SigningKey.from_string(private_key_bytes, curve=SECP256k1)

def encrypt_data(data: bytes, password: str) -> bytes:
    # This block is correctly indented
    salt = get_random_bytes(SALT_SIZE)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return salt + cipher.iv + ciphertext

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    # This block is correctly indented
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE+AES.block_size]
    ciphertext = encrypted_data[SALT_SIZE+AES.block_size:]
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def save_wallet(mnemonic: str, password: str):
    # This block is correctly indented
    encrypted_mnemonic = encrypt_data(mnemonic.encode(), password)
    with open(WALLET_FILE, 'wb') as f: f.write(encrypted_mnemonic)
    print(f"{Colors.GREEN}✅ Wallet saved securely to {WALLET_FILE}{Colors.ENDC}")

def get_unlocked_wallet() -> SigningKey:
    # This block is correctly indented
    if not os.path.exists(WALLET_FILE):
        print(f"{Colors.RED}❌ Error: Wallet file '{WALLET_FILE}' not found. Please create or import a wallet first.{Colors.ENDC}")
        return None
    password = getpass.getpass("Enter password to unlock wallet: ")
    with open(WALLET_FILE, 'rb') as f: encrypted_data = f.read()
    try:
        mnemonic = decrypt_data(encrypted_data, password).decode()
        return get_keys_from_mnemonic(mnemonic)
    except (ValueError, KeyError):
        print(f"{Colors.RED}❌ Error: Incorrect password or corrupted wallet file.{Colors.ENDC}")
        return None

def load_mnemonic(password: str) -> str:
    # This block is correctly indented
    if not os.path.exists(WALLET_FILE):
        print(f"{Colors.RED}❌ Error: Wallet file '{WALLET_FILE}' not found.{Colors.ENDC}")
        return None
    with open(WALLET_FILE, 'rb') as f: encrypted_data = f.read()
    try:
        return decrypt_data(encrypted_data, password).decode()
    except (ValueError, KeyError):
        print(f"{Colors.RED}❌ Error: Incorrect password or corrupted wallet file.{Colors.ENDC}")
        return None

# =============================================================================
# API INTERACTION
# =============================================================================
def get_address_info(address: str):
    # This block is correctly indented
    try:
        response = requests.get(f"{BFF_API_URL}/address/{address}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}❌ Error connecting to BunkNet API: {e}{Colors.ENDC}")
        return None

def send_transaction(key_pair: SigningKey, recipient: str, amount: float, fee: float):
    # This block is correctly indented
    public_key_hex = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    tx_data = {'sender': public_key_hex, 'recipient': recipient, 'amount': amount, 'fee': fee}
    tx_data_str = json.dumps(tx_data, sort_keys=True)
    tx_hash = hashlib.sha256(tx_data_str.encode()).digest()
    signature = binascii.hexlify(key_pair.sign(tx_hash)).decode()
    payload = {**tx_data, 'public_key': public_key_hex, 'signature': signature}
    try:
        response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload)
        response.raise_for_status()
        print(f"{Colors.GREEN}✅ Transaction sent successfully!{Colors.ENDC}")
        print(response.json().get('message'))
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}❌ Error sending transaction: {e.response.text if e.response else e}{Colors.ENDC}")
        
# =============================================================================
# INTERACTIVE MENU HANDLERS
# =============================================================================

def handle_manage_wallet():
    # This block is correctly indented
    if os.path.exists(WALLET_FILE):
        print(f"{Colors.YELLOW}⚠️ Warning: A wallet file ('{WALLET_FILE}') already exists.{Colors.ENDC}")
        overwrite = input("Continuing will overwrite it. Are you sure? (yes/no): ").lower()
        if overwrite != 'yes':
            print("Operation cancelled.")
            return

    choice = input("Do you want to (G)enerate a new wallet or (I)mport an existing one? ").lower()
    if choice == 'g':
        mnemonic = mnemo.generate(strength=128)
        print(f"\n{Colors.HEADER}{Colors.BOLD}✨ Your New Wallet Seed Phrase ✨{Colors.ENDC}"); print("=" * 35); print(f"\n{Colors.CYAN}{mnemonic}{Colors.ENDC}\n"); print("=" * 35)
        print(f"{Colors.RED}{Colors.BOLD}🛑 IMPORTANT: Write this phrase down and store it securely. It's the only way to recover your wallet.{Colors.ENDC}")
        password = getpass.getpass("Enter a strong password to encrypt this wallet: ")
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password: print(f"{Colors.RED}❌ Passwords do not match.{Colors.ENDC}"); return
        save_wallet(mnemonic, password)
    elif choice == 'i':
        mnemonic = input("Enter your 12-word seed phrase: ").strip().lower()
        if not mnemo.check(mnemonic): print(f"{Colors.RED}❌ Invalid seed phrase.{Colors.ENDC}"); return
        password = getpass.getpass("Enter a strong password to encrypt this wallet: ")
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password: print(f"{Colors.RED}❌ Passwords do not match.{Colors.ENDC}"); return
        save_wallet(mnemonic, password)
    else:
        print(f"{Colors.RED}Invalid choice.{Colors.ENDC}")
    
def handle_address():
    # This block is correctly indented
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    print(f"\n{Colors.CYAN}🔑 Your BunkNet Public Address:{Colors.ENDC}"); print(public_key)
    
def handle_balance():
    # This block is correctly indented
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    if not info: return
    print(f"\n{Colors.GREEN}💰 Balance: {info.get('balance', 0):.4f} $BUNK{Colors.ENDC}")

def handle_history():
    # This block is correctly indented
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    if not info: return
    transactions = info.get('transactions', [])
    
    print(f"\n{Colors.HEADER}📜 Transaction History:{Colors.ENDC}")
    if not transactions:
        print("No transactions found.")
        return
        
    for tx in reversed(transactions):
        if tx['sender'] == '0' and tx['recipient'] == public_key:
            print(f"{Colors.GREEN}IN {Colors.ENDC} | From: Network Reward      | Amount: {tx['amount']:.2f}")
        else:
            direction = "OUT" if tx['sender'] == public_key else "IN "
            color_code = Colors.RED if direction == "OUT" else Colors.GREEN
            other_party = tx['recipient'] if direction == "OUT" else tx['sender']
            print(f"{color_code}{direction}{Colors.ENDC} | To/From: {other_party[:15]:<15} | Amount: {tx['amount']:.2f} | Fee: {tx.get('fee', 0):.4f}")

def handle_send():
    # This block is correctly indented
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    public_key = binascii.hexlify(key_pair.get_verifying_key().to_string()).decode()
    info = get_address_info(public_key)
    if not info: return
    balance = info.get('balance', 0)
    
    try:
        recipient = input("Enter recipient address: ")
        amount = float(input("Enter amount to send: "))
        fee = float(input("Enter transaction fee (default 0.01): ") or "0.01")
    except ValueError:
        print(f"{Colors.RED}❌ Invalid amount or fee. Please enter a number.{Colors.ENDC}")
        return

    if (amount + fee) > balance:
        print(f"{Colors.RED}❌ Error: Insufficient funds. Your balance is {balance:.4f} $BUNK.{Colors.ENDC}")
        return

    print(f"\n{Colors.YELLOW}--- Transaction Summary ---{Colors.ENDC}")
    print(f"  Recipient: {recipient}")
    print(f"  Amount:    {amount:.4f} $BUNK")
    print(f"  Fee:       {fee:.4f} $BUNK")
    print("-" * 27)
    print(f"  Total:     {(amount + fee):.4f} $BUNK")
    print("-" * 27)
    
    confirm = input("Type 'yes' to confirm and send this transaction: ")
    if confirm.lower() != 'yes':
        print("Transaction cancelled.")
        return
    
    print(f"\n{Colors.BLUE}Sending transaction...{Colors.ENDC}")
    send_transaction(key_pair, recipient, amount, fee)

def handle_backup():
    # This block is correctly indented
    password = getpass.getpass("Enter password to unlock wallet: ")
    mnemonic = load_mnemonic(password)
    if not mnemonic: return
    
    print("\n" + "="*50 + f"\n{Colors.RED}{Colors.BOLD}🛑 WARNING: SENSITIVE INFORMATION AHEAD 🛑{Colors.ENDC}");
    print("Anyone who sees this phrase can steal your funds.");
    print("Ensure you are in a private and secure location.\n" + "="*50 + "\n")
    print(f"{Colors.CYAN}🔑 Your private seed phrase is:\n\n{mnemonic}\n{Colors.ENDC}")

# =============================================================================
# MAIN APPLICATION LOOP
# =============================================================================
def display_menu():
    # This function and its contents are correctly indented
    """Clears the screen and displays the main menu."""
    os.system('cls' if os.name == 'nt' else 'clear')
    art = rf"""
{Colors.CYAN}************************************************************************
* /$$$$$$$                      /$$       /$$   /$$             /$$    *
*| $$__  $$                    | $$      | $$$ | $$            | $$    *
*| $$  \ $$ /$$   /$$ /$$$$$$$ | $$   /$$| $$$$| $$  /$$$$$$  /$$$$$$  *
*| $$$$$$$ | $$  | $$| $$__  $$| $$  /$$/| $$ $$ $$ /$$__  $$|_  $$_/  *
*| $$__  $$| $$  | $$| $$  \ $$| $$$$$$/ | $$  $$$$| $$$$$$$$  | $$    *
*| $$  \ $$| $$  | $$| $$  | $$| $$_  $$ | $$\  $$$| $$_____/  | $$ /$$*
*| $$$$$$$/|  $$$$$$/| $$  | $$| $$ \  $$| $$ \  $$|  $$$$$$$  |  $$$$/*
*|_______/  \______/ |__/  |__/|__/  \__/|__/  \__/ \_______/   \___/  *
* *
*          /$$      /$$           /$$ /$$             /$$              *
*          | $$  /$ | $$          | $$| $$            | $$             *
*          | $$ /$$$| $$  /$$$$$$ | $$| $$  /$$$$$$  /$$$$$$           *
*          | $$/$$ $$ $$ |____  $$| $$| $$ /$$__  $$|_  $$_/           *
*          | $$$$_  $$$$  /$$$$$$$| $$| $$| $$$$$$$$  | $$             *
*          | $$$/ \  $$$ /$$__  $$| $$| $$| $$_____/  | $$ /$$         *
*          | $$/   \  $$|  $$$$$$$| $$| $$|  $$$$$$$  |  $$$$/         *
*          |__/     \__/ \_______/|__/|__/ \_______/   \___/           *
************************************************************************{Colors.ENDC}
"""
    print(art)
    print(f"    {Colors.BLUE}1.{Colors.ENDC} Create or Import a Wallet")
    print(f"    {Colors.BLUE}2.{Colors.ENDC} View Address")
    print(f"    {Colors.BLUE}3.{Colors.ENDC} View Balance")
    print(f"    {Colors.BLUE}4.{Colors.ENDC} View Seed Phrase (Backup)")
    print(f"    {Colors.BLUE}5.{Colors.ENDC} Send $BUNK")
    print(f"    {Colors.BLUE}6.{Colors.ENDC} View Transaction History")
    print(f"\n    {Colors.YELLOW}q.{Colors.ENDC} Quit")
    print("=" * 88)

def main():
    # IMPORTANT: The 'while' loop below MUST be indented inside the main() function
    """The main function to run the interactive tool."""
    while True:
        # These lines MUST be indented inside the 'while' loop
        display_menu()
        choice = input(f"{Colors.BOLD}Enter your choice: {Colors.ENDC}").lower()

        if choice == '1':
            # This line MUST be indented inside the 'if' statement
            handle_manage_wallet()
        elif choice == '2':
            handle_address()
        elif choice == '3':
            handle_balance()
        elif choice == '4':
            handle_backup()
        elif choice == '5':
            handle_send()
        elif choice == '6':
            handle_history()
        elif choice == 'q':
            print("Goodbye!")
            break
        else:
            print(f"{Colors.RED}Invalid choice, please try again.{Colors.ENDC}")

        # This 'if' statement MUST be indented inside the 'while' loop
        if choice != 'q':
            input(f"\n{Colors.YELLOW}Press Enter to return to the menu...{Colors.ENDC}")

# This is the final part of the script that makes it run
if __name__ == '__main__':
    main()
            
