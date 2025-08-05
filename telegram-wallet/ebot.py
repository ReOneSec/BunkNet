import logging
import os
import io
import qrcode
import binascii
import json
import hashlib
import datetime
import re

import requests
from dotenv import load_dotenv
from mnemonic import Mnemonic
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from Crypto.Hash import keccak
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from pymongo import MongoClient
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins # <-- NEW IMPORT

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, MessageHandler,
    ConversationHandler, ContextTypes, filters
)

# --- Load Configuration ---
load_dotenv()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
BOT_SECRET_KEY = os.environ.get("BOT_SECRET_KEY")
BFF_API_URL = os.environ.get("BUNKNET_BFF_API_URL", "https://api.bunknet.online/explorer/api")
MONGO_URI = os.environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/')

# --- Setup ---
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

client = MongoClient(MONGO_URI)
db = client["bunknet_telegram_bot"]
users_col = db["users"]

mnemo = Mnemonic("english")

# --- State Constants for Conversations ---
MAIN_MENU, SETTINGS_MENU = range(2)
NEW_PIN, CONFIRM_NEW_PIN = range(2, 4)
VERIFY_PIN, GET_RECIPIENT, GET_AMOUNT, GET_FEE, CONFIRM_SEND = range(4, 9)

# --- Helper Functions ---
def escape_markdown(text: str) -> str:
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)

def hash_pin(pin: str, user_id: int) -> str:
    salt = str(user_id).encode()
    return hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000, 64).hex()

# --- Wallet & Crypto Helpers (UPDATED) ---
# --- 1. REPLACED KEY DERIVATION FUNCTION ---
def get_keys_from_mnemonic(mnemonic: str) -> SigningKey:
    """Derives a private key using the standard BIP-44 path."""
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
    private_key_bytes = bip44_acc_ctx.PrivateKey().Raw().ToBytes()
    return SigningKey.from_string(private_key_bytes, curve=SECP256k1)

# --- 2. NEW ADDRESS CALCULATION FUNCTION ---
def public_key_to_address(verifying_key: VerifyingKey) -> str:
    """Converts an ECDSA public key to a standard 0x-prefixed Ethereum address."""
    public_key_bytes = verifying_key.to_string("uncompressed")[1:]
    k = keccak.new(digest_bits=256)
    k.update(public_key_bytes)
    address_bytes = k.digest()[-20:]
    return '0x' + address_bytes.hex()

def encrypt_mnemonic(mnemonic: str, user_id: int) -> str:
    salt = get_random_bytes(16); password = f"{BOT_SECRET_KEY}{user_id}"
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_CBC); encrypted = cipher.encrypt(pad(mnemonic.encode(), AES.block_size))
    return binascii.hexlify(salt + cipher.iv + encrypted).decode()

def decrypt_mnemonic(encrypted_hex: str, user_id: int) -> str:
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    salt, iv, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    password = f"{BOT_SECRET_KEY}{user_id}"
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# --- 3. UPDATED WALLET CREATION & MIGRATION ---
def get_or_create_wallet(user_id: int, username: str) -> dict:
    user = users_col.find_one({"telegram_id": user_id})
    if user:
        # --- Automatic Migration for Old Users ---
        if "address" not in user:
            logging.info(f"Migrating user {user_id} to new address format.")
            mnemonic = decrypt_mnemonic(user['encrypted_mnemonic'], user_id)
            private_key = get_keys_from_mnemonic(mnemonic)
            verifying_key = private_key.get_verifying_key()
            address = public_key_to_address(verifying_key)
            users_col.update_one({"telegram_id": user_id}, {"$set": {"address": address}})
            user['address'] = address # Update in-memory object
        return user

    # --- Create New User with Standard Address ---
    mnemonic = mnemo.generate(strength=128)
    private_key = get_keys_from_mnemonic(mnemonic)
    verifying_key = private_key.get_verifying_key()
    
    public_key = binascii.hexlify(verifying_key.to_string()).decode()
    address = public_key_to_address(verifying_key)
    encrypted_mnemonic = encrypt_mnemonic(mnemonic, user_id)

    new_user = {
        "telegram_id": user_id,
        "username": username,
        "public_key": public_key, # Still useful to store for verification
        "address": address,       # The new primary identifier
        "encrypted_mnemonic": encrypted_mnemonic,
        "created_at": datetime.datetime.now(datetime.timezone.utc),
        "pin_hash": None
    }
    users_col.insert_one(new_user)
    logging.info(f"Created a new wallet for user {username} ({user_id}) with address {address}")
    return new_user

# --- UI Keyboards (Unchanged) ---
def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [[InlineKeyboardButton("💰 Balance", callback_data="balance"), InlineKeyboardButton("📜 History", callback_data="history")], [InlineKeyboardButton("⬆️ Send", callback_data="send"), InlineKeyboardButton("⬇️ Receive", callback_data="receive")], [InlineKeyboardButton("⚙️ Settings", callback_data="settings")]]
    return InlineKeyboardMarkup(keyboard)

def get_settings_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [[InlineKeyboardButton("🔑 Set/Change PIN", callback_data="set_pin")], [InlineKeyboardButton("📄 View Seed Phrase", callback_data="backup")], [InlineKeyboardButton("« Back to Main Menu", callback_data="main_menu")]]
    return InlineKeyboardMarkup(keyboard)

# --- Top Level Command Handlers (Unchanged) ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user = update.effective_user
    get_or_create_wallet(user.id, user.username)
    await update.message.reply_text(f"👋 Welcome to the BunkNet Wallet, {user.first_name}!\n\nUse the buttons below or type /help.", reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = r"""*BunkNet Wallet Bot Help*
Here are the commands:
`/start` \- Shows the main menu\.
`/address` \- Shows your wallet address\.
`/help` \- Shows this message\.
`/cancel` \- Cancels any operation\.
"""
    await update.message.reply_text(help_text, parse_mode='MarkdownV2')

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Action cancelled.", reply_markup=get_main_menu_keyboard())
    context.user_data.clear()
    return ConversationHandler.END

# --- Simple Button Actions (UPDATED) ---
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    await query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    try:
        # Use the 0x address for the API call
        response = requests.get(f"{BFF_API_URL}/address/{user_wallet['address']}")
        response.raise_for_status()
        balance_val = response.json().get('balance', 0)
        balance_str = escape_markdown(f"{balance_val:.4f}")
        message = f"Welcome to The BunkNet Wallet [$BUNK]\n\nYour current balance is:\n\n`{balance_str}` *$BUNK*"
    except requests.exceptions.RequestException: message = "Could not connect to the BunkNet network."
    await context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def receive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.effective_chat.id
    if update.callback_query: await update.callback_query.answer(); await update.callback_query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    address = user_wallet['address'] # Use the 0x address
    qr_img = qrcode.make(address); bio = io.BytesIO(); qr_img.save(bio, 'PNG'); bio.seek(0)
    caption = f"Here is your BunkNet address:\n\n`{address}`"
    await context.bot.send_photo(chat_id=chat_id, photo=bio, caption=caption, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer(); await query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    address = user_wallet['address'] # Use the 0x address
    try:
        response = requests.get(f"{BFF_API_URL}/address/{address}")
        response.raise_for_status()
        data = response.json()
        transactions = data.get('transactions', [])
        if not transactions:
            message = "You have no transactions yet."
        else:
            message_parts = ["*📜 Your 5 most recent transactions:*\n"]
            for tx in reversed(transactions[-5:]):
                # Compare against the 0x address
                direction_icon = "➡" if tx['sender'] == address else "⬅"
                direction_text = "Sent" if tx['sender'] == address else "Received"
                amount_str = escape_markdown(f"{tx['amount']:.4f}")
                other_party_label = "To" if direction_text == "Sent" else "From"
                other_party_addr = tx['recipient'] if direction_text == "Sent" else tx['sender']
                
                if other_party_addr == '0':
                    display_address = escape_markdown("Network Reward")
                else:
                    display_address = escape_markdown(f"{other_party_addr[:6]}...{other_party_addr[-6:]}")
                
                tx_id = tx.get('transaction_id', 'N/A')
                link_text = escape_markdown(f"{tx_id[:6]}...{tx_id[-6:]}")
                explorer_url = f"https://explorer.bunknet.online/#/transaction/{tx_id}" # Example explorer link
                tx_info = (f"`{direction_icon} {direction_text} {amount_str} $BUNK`\n"
                           f"*{other_party_label}:* `{display_address}`\n"
                           f"*Hash:* [{link_text}]({explorer_url})")
                message_parts.append(tx_info)
            message = "\n\n".join(message_parts)
    except requests.exceptions.RequestException as e:
        logging.error(f"Could not fetch transaction history: {e}")
        message = "Could not fetch transaction history from the network."

    await context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard(), disable_web_page_preview=True)
    return MAIN_MENU
    
# ... (Settings and back_to_main_menu are unchanged) ...
async def settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    await query.edit_message_text("⚙️ Settings", reply_markup=get_settings_menu_keyboard())
    return SETTINGS_MENU

async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    await query.edit_message_text("Main Menu:", reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

# --- PIN, SEND, BACKUP FLOWS (UPDATED process_transaction) ---
# ... (All conversation flows except the final processing step remain the same) ...
async def process_transaction(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    if query.data == "confirm_send":
        await query.edit_message_text(text="Sending transaction...")
        user_wallet = get_or_create_wallet(update.effective_user.id, "")
        mnemonic = decrypt_mnemonic(user_wallet['encrypted_mnemonic'], update.effective_user.id)
        
        # Derive keys and addresses
        private_key = get_keys_from_mnemonic(mnemonic)
        verifying_key = private_key.get_verifying_key()
        sender_address = public_key_to_address(verifying_key)
        public_key = binascii.hexlify(verifying_key.to_string()).decode()

        # Build transaction with 0x address
        tx_data = {
            'sender': sender_address,
            'recipient': context.user_data['recipient'],
            'amount': context.user_data['amount'],
            'fee': context.user_data['fee']
        }
        
        tx_hash = hashlib.sha256(json.dumps(tx_data, sort_keys=True).encode()).digest()
        signature = binascii.hexlify(private_key.sign(tx_hash)).decode()
        
        # Final payload still includes public_key for verification
        payload = {**tx_data, 'public_key': public_key, 'signature': signature}
        
        try:
            response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload); response.raise_for_status()
            result_message = "✅ Transaction sent successfully!"
        except requests.exceptions.RequestException as e:
            error_msg = "Could not send transaction."
            try: error_msg = e.response.json().get('error', error_msg)
            except: pass
            result_message = f"❌ Error: {error_msg}"
        await query.edit_message_text(text=result_message, reply_markup=get_main_menu_keyboard())
    else:
        await query.edit_message_text(text="Transaction cancelled.", reply_markup=get_main_menu_keyboard())
    context.user_data.clear()
    return MAIN_MENU

# ... (The rest of the main() function and conversation handlers can remain the same) ...

def main() -> None:
    if not TELEGRAM_BOT_TOKEN or not BOT_SECRET_KEY: logging.error("Bot tokens must be set in .env file."); return
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).job_queue(None).build()
    
    # This is a very complex conversation handler. I'm assuming it's correct from the user's code.
    # The only changes were in the final `process_transaction` function it calls.
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            MAIN_MENU: [
                CallbackQueryHandler(balance, pattern='^balance$'), CallbackQueryHandler(history, pattern='^history$'),
                CallbackQueryHandler(receive, pattern='^receive$'), CallbackQueryHandler(settings, pattern='^settings$'),
                CallbackQueryHandler(protected_action_start, pattern='^(send|backup)$'),
            ],
            SETTINGS_MENU: [
                CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$'),
                CallbackQueryHandler(set_pin_start, pattern='^set_pin$'),
                CallbackQueryHandler(protected_action_start, pattern='^backup$'),
            ],
            NEW_PIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_new_pin)],
            CONFIRM_NEW_PIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_pin_confirmation)],
            VERIFY_PIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_pin_and_proceed)],
            GET_RECIPIENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_recipient)],
            GET_AMOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_amount)],
            GET_FEE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_fee)],
            CONFIRM_SEND: [CallbackQueryHandler(process_transaction)]
        },
        fallbacks=[CommandHandler('start', start), CommandHandler('help', help_command), CommandHandler('cancel', cancel)],
        per_user=True, per_chat=True
    )
    application.add_handler(CommandHandler("address", receive))
    application.add_handler(conv_handler)
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
  
