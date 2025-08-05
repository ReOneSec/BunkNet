import getpass
import json
import os
import sys
import hashlib
import binascii

import requests
from mnemonic import Mnemonic
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from Crypto.Hash import keccak
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes


# --- Configuration ---
# Updated to your live API URL
BFF_API_URL = "https://api.bunknet.online/explorer/api"
WALLET_FILE = "wallet.dat"
SALT_SIZE = 16
AES_KEY_LEN = 32
PBKDF2_ITERATIONS = 100000

# ANSI Color Codes for better UI
class Colors:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'; GREEN = '\033[92m';
    YELLOW = '\033[93m'; RED = '\033[91m'; ENDC = '\033[0m'; BOLD = '\033[1m';

# =============================================================================
# CRYPTOGRAPHY & WALLET HELPERS
# =============================================================================

mnemo = Mnemonic("english")

# --- 1. REPLACED KEY DERIVATION FUNCTION ---

def get_keys_from_mnemonic(mnemonic: str) -> SigningKey:
    """
    Derives an ECDSA private key from a BIP39 mnemonic using the standard
    Ethereum derivation path (m/44'/60'/0'/0/0) to be compatible with MetaMask/Ethers.js.
    """
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)

    # --- THIS IS THE LINE THAT WAS FIXED ---
    # We now use Bip44Changes.CHAIN_EXT instead of the number 0
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

    private_key_bytes = bip44_acc_ctx.PrivateKey().Raw().ToBytes()
    return SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
# --- 2. NEW ADDRESS CALCULATION FUNCTION ---
def public_key_to_address(verifying_key: VerifyingKey) -> str:
    """Converts an ECDSA public key to a standard 0x-prefixed Ethereum address."""
    # Get the 64-byte uncompressed public key (x and y coordinates)
    public_key_bytes = verifying_key.to_string("uncompressed")[1:]
    
    # Keccak-256 hash the public key
    k = keccak.new(digest_bits=256)
    k.update(public_key_bytes)
    
    # Take the last 20 bytes of the hash and prefix with '0x'
    address_bytes = k.digest()[-20:]
    return '0x' + address_bytes.hex()

# --- (Encryption functions remain the same) ---
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
    print(f"{Colors.GREEN}✅ Wallet saved securely to {WALLET_FILE}{Colors.ENDC}")

def get_unlocked_wallet() -> SigningKey:
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
# API INTERACTION (UPDATED TO USE 0x ADDRESS)
# =============================================================================
def get_address_info(address: str):
    try:
        response = requests.get(f"{BFF_API_URL}/address/{address}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}❌ Error connecting to BunkNet API: {e}{Colors.ENDC}")
        return None

# --- 3. UPDATED send_transaction ---
def send_transaction(key_pair: SigningKey, recipient: str, amount: float, fee: float):
    verifying_key = key_pair.get_verifying_key()
    sender_address = public_key_to_address(verifying_key)
    public_key_hex = binascii.hexlify(verifying_key.to_string()).decode()

    # The sender field should now be the 0x address
    tx_data = {'sender': sender_address, 'recipient': recipient, 'amount': amount, 'fee': fee}
    
    # Sort keys to ensure consistent hash
    tx_data_str = json.dumps(tx_data, sort_keys=True)
    tx_hash = hashlib.sha256(tx_data_str.encode()).digest()
    signature = binascii.hexlify(key_pair.sign(tx_hash)).decode()
    
    # The payload still includes the full public key for backend verification
    payload = {**tx_data, 'public_key': public_key_hex, 'signature': signature}
    
    try:
        response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload)
        response.raise_for_status()
        print(f"{Colors.GREEN}✅ Transaction sent successfully!{Colors.ENDC}")
        print(response.json().get('message'))
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}❌ Error sending transaction: {e.response.text if e.response else e}{Colors.ENDC}")
        
# =============================================================================
# INTERACTIVE MENU HANDLERS (UPDATED)
# =============================================================================

def handle_manage_wallet():
    # This function's logic remains the same
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

# --- 4. UPDATED handle_address ---
def handle_address():
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    address = public_key_to_address(key_pair.get_verifying_key())
    print(f"\n{Colors.CYAN}🔑 Your BunkNet Address:{Colors.ENDC}"); print(address)
    
# --- 5. UPDATED handle_balance ---
def handle_balance():
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    address = public_key_to_address(key_pair.get_verifying_key())
    info = get_address_info(address)
    if not info: return
    print(f"\n{Colors.GREEN}💰 Balance: {info.get('balance', 0):.4f} $BUNK{Colors.ENDC}")

# --- 6. UPDATED handle_history ---
def handle_history():
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    address = public_key_to_address(key_pair.get_verifying_key())
    info = get_address_info(address)
    if not info: return
    transactions = info.get('transactions', [])
    
    print(f"\n{Colors.HEADER}📜 Transaction History:{Colors.ENDC}")
    if not transactions:
        print("No transactions found.")
        return
        
    for tx in reversed(transactions):
        # Now we compare against the 0x address
        if tx['sender'] == '0' and tx['recipient'] == address:
            print(f"{Colors.GREEN}IN {Colors.ENDC} | From: Network Reward      | Amount: {tx['amount']:.2f}")
        else:
            direction = "OUT" if tx['sender'] == address else "IN "
            color_code = Colors.RED if direction == "OUT" else Colors.GREEN
            other_party = tx['recipient'] if direction == "OUT" else tx['sender']
            print(f"{color_code}{direction}{Colors.ENDC} | To/From: {other_party[:15]:<15} | Amount: {tx['amount']:.2f} | Fee: {tx.get('fee', 0):.4f}")

# --- 7. UPDATED handle_send ---
def handle_send():
    key_pair = get_unlocked_wallet()
    if not key_pair: return
    address = public_key_to_address(key_pair.get_verifying_key())
    info = get_address_info(address)
    if not info: return
    balance = info.get('balance', 0)
    
    try:
        recipient = input("Enter recipient address (must start with 0x): ")
        if not recipient.startswith("0x"): raise ValueError("Invalid address format")
        amount = float(input("Enter amount to send: "))
        fee = float(input("Enter transaction fee (default 0.01): ") or "0.01")
    except ValueError:
        print(f"{Colors.RED}❌ Invalid input. Please check the address and numbers.{Colors.ENDC}")
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
    # This function does not need changes
    os.system('cls' if os.name == 'nt' else 'clear')
    art = rf"""
{Colors.CYAN}*****************************************
* ____              _    _   _      _   *
*| __ ) _   _ _ __ | | _| \ | | ___| |_ *
*|  _ \| | | | '_ \| |/ /  \| |/ _ \ __|*
*| |_) | |_| | | | |   <| |\  |  __/ |_ *
*|____/ \__,_|_| |_|_|\_\_| \_|\___|\__|*
*     __        __    _ _      _        *
*     \ \      / /_ _| | | ___| |_      *
*      \ \ /\ / / _` | | |/ _ \ __|     *
*       \ V  V / (_| | | |  __/ |_      *
*        \_/\_/ \__,_|_|_|\___|\__|     *
*****************************************{Colors.ENDC}
"""
    print(art)
    print(f"{Colors.HEADER}              Wallet v1.0{Colors.ENDC}")
    print("=========================================")
    print(f" {Colors.BLUE}1.{Colors.ENDC} Create or Import a Wallet")
    print(f" {Colors.BLUE}2.{Colors.ENDC} View Address")
    print(f" {Colors.BLUE}3.{Colors.ENDC} View Balance")
    print(f" {Colors.BLUE}4.{Colors.ENDC} View Seed Phrase (Backup)")
    print(f" {Colors.BLUE}5.{Colors.ENDC} Send $BUNK")
    print(f" {Colors.BLUE}6.{Colors.ENDC} View Transaction History")
    print(f"\n {Colors.YELLOW}q.{Colors.ENDC} Quit")
    print("=========================================")

def main():
    # This function does not need changes
    while True:
        display_menu()
        choice = input(f"{Colors.BOLD}Enter your choice: {Colors.ENDC}").lower()

        if choice == '1':
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

        if choice != 'q':
            input(f"\n{Colors.YELLOW}Press Enter to return to the menu...{Colors.ENDC}")

if __name__ == '__main__':
    main()
  
