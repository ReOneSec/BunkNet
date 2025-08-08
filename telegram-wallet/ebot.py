import logging
import os
import io
import qrcode
import json
import hashlib
import datetime
import re

import requests
from dotenv import load_dotenv
from mnemonic import Mnemonic
# --- CORRECTED IMPORT TO MATCH DOCUMENTATION ---
from eth_keys import keys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from pymongo import MongoClient
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

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
VERIFY_PIN, GET_RECIPIENT, GET_AMOUNT, CONFIRM_SEND = range(4, 8)

# --- Helper Functions ---
def escape_markdown(text: str) -> str:
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)

def hash_pin(pin: str, user_id: int) -> str:
    salt = str(user_id).encode()
    return hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000, 64).hex()

# --- Wallet & Crypto Helpers (UPDATED) ---
def get_private_key_from_mnemonic(mnemonic: str) -> keys.PrivateKey:
    """Derives an eth_keys PrivateKey using the standard BIP-44 path."""
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    private_key_bytes = bip44_acc_ctx.PrivateKey().Raw().ToBytes()
    return keys.PrivateKey(private_key_bytes)

def public_key_to_address(public_key: keys.PublicKey) -> str:
    """Converts an eth_keys PublicKey object to an Ethereum checksum address."""
    return public_key.to_checksum_address()

def encrypt_mnemonic(mnemonic: str, user_id: int) -> str:
    key_seed = f"{BOT_SECRET_KEY}{user_id}".encode()
    salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', key_seed, salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted, tag = cipher.encrypt_and_digest(mnemonic.encode())
    return (salt + cipher.nonce + tag + encrypted).hex()

def decrypt_mnemonic(encrypted_hex: str, user_id: int) -> str:
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    salt, nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:48], encrypted_bytes[48:]
    key_seed = f"{BOT_SECRET_KEY}{user_id}".encode()
    key = hashlib.pbkdf2_hmac('sha256', key_seed, salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def get_or_create_wallet(user_id: int, username: str) -> dict:
    user = users_col.find_one({"telegram_id": user_id})
    if user:
        return user

    mnemonic = mnemo.generate(strength=128)
    private_key = get_private_key_from_mnemonic(mnemonic)
    public_key = private_key.public_key
    address = public_key.to_checksum_address()
    encrypted_mnemonic = encrypt_mnemonic(mnemonic, user_id)
    
    new_user = {
        "telegram_id": user_id,
        "username": username,
        "public_key": public_key.to_bytes().hex(),
        "address": address,
        "encrypted_mnemonic": encrypted_mnemonic,
        "created_at": datetime.datetime.now(datetime.timezone.utc),
        "pin_hash": None
    }
    users_col.insert_one(new_user)
    logging.info(f"Created a new wallet for user {username} ({user_id}) with address {address}")
    return new_user

# --- UI Keyboards ---
def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [[InlineKeyboardButton("💰 Balance", callback_data="balance"), InlineKeyboardButton("📜 History", callback_data="history")], [InlineKeyboardButton("⬆️ Send", callback_data="send"), InlineKeyboardButton("⬇️ Receive", callback_data="receive")], [InlineKeyboardButton("⚙️ Settings", callback_data="settings")]]
    return InlineKeyboardMarkup(keyboard)

def get_settings_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [[InlineKeyboardButton("🔑 Set/Change PIN", callback_data="set_pin")], [InlineKeyboardButton("📄 View Seed Phrase", callback_data="backup")], [InlineKeyboardButton("« Back to Main Menu", callback_data="main_menu")]]
    return InlineKeyboardMarkup(keyboard)

# --- Top Level Command Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user = update.effective_user
    get_or_create_wallet(user.id, user.username)
    await update.message.reply_text(f"👋 Welcome to the BunkNet Wallet, {user.first_name}!\n\nUse the buttons below or type /help.", reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = r"""*BunkNet Wallet Bot Help*
`/start` \- Shows the main menu\.
`/address` \- Shows your wallet address\.
`/help` \- Shows this message\.
`/cancel` \- Cancels any operation\.
"""
    await update.message.reply_text(help_text, parse_mode='MarkdownV2')

# --- Conversation and Action Handlers ---
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    query = update.callback_query
    if query:
        await query.answer()
        await query.edit_message_text("Action cancelled.", reply_markup=get_main_menu_keyboard())
    else:
        await update.message.reply_text("Action cancelled.", reply_markup=get_main_menu_keyboard())
    return ConversationHandler.END

async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer(); await query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    try:
        response = requests.get(f"{BFF_API_URL}/address/{user_wallet['address']}")
        response.raise_for_status()
        balance_val = response.json().get('balance', 0)
        balance_str = escape_markdown(f"{balance_val:.4f}")
        message = f"Your current balance is:\n\n`{balance_str}` *$BUNK*"
    except requests.exceptions.RequestException:
        message = escape_markdown("Could not connect to the BunkNet network.")
    await context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def receive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.effective_chat.id
    if update.callback_query: await update.callback_query.answer(); await update.callback_query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    address = user_wallet['address']
    qr_img = qrcode.make(address); bio = io.BytesIO(); qr_img.save(bio, 'PNG'); bio.seek(0)
    caption = f"Here is your BunkNet address:\n\n`{address}`"
    await context.bot.send_photo(chat_id=chat_id, photo=bio, caption=caption, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer(); await query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    address = user_wallet['address']
    try:
        response = requests.get(f"{BFF_API_URL}/address/{address}"); response.raise_for_status()
        transactions = response.json().get('transactions', [])
        if not transactions:
            message = escape_markdown("You have no transactions yet.")
        else:
            message_parts = ["*📜 Your 5 most recent transactions:*\n"]
            for tx in reversed(transactions[-5:]):
                direction_icon = "➡" if tx['sender'] == address else "⬅"
                direction_text = "Sent" if tx['sender'] == address else "Received"
                amount_str = escape_markdown(f"{float(tx['amount']):.4f}")
                other_party_addr = tx['recipient'] if direction_text == "Sent" else tx['sender']
                display_address = escape_markdown("Network Reward") if other_party_addr == '0' else escape_markdown(f"{other_party_addr[:6]}...{other_party_addr[-6:]}")
                tx_id = tx.get('transaction_id', 'N/A')
                link_text = escape_markdown(f"{tx_id[:6]}...{tx_id[-6:]}")
                explorer_url = f"https://explorer.bunknet.online/#/transaction/{tx_id}"
                tx_info = (f"`{direction_icon} {direction_text} {amount_str} $BUNK`\n*To/From:* `{display_address}`\n*Hash:* [{link_text}]({explorer_url})")
                message_parts.append(tx_info)
            message = "\n\n".join(message_parts)
    except requests.exceptions.RequestException as e:
        logging.error(f"Could not fetch transaction history: {e}")
        message = escape_markdown("Could not fetch transaction history from the network.")
    await context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard(), disable_web_page_preview=True)
    return MAIN_MENU
    
async def settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    await query.edit_message_text("⚙️ Settings", reply_markup=get_settings_menu_keyboard())
    return SETTINGS_MENU

async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    await query.edit_message_text("Main Menu:", reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def protected_action_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    user_wallet = get_or_create_wallet(query.from_user.id, "")
    if not user_wallet.get('pin_hash'):
        await query.edit_message_text("Please set a PIN in Settings first.", reply_markup=get_settings_menu_keyboard())
        return SETTINGS_MENU
    context.user_data['next_action'] = query.data
    await query.edit_message_text(f"Please enter your PIN to authorize this action.")
    return VERIFY_PIN

async def check_pin_and_proceed(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    pin = update.message.text; await update.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    if hash_pin(pin, update.effective_user.id) != user_wallet.get('pin_hash'):
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Incorrect PIN. Action cancelled.", reply_markup=get_main_menu_keyboard())
        return MAIN_MENU
    next_action = context.user_data.get('next_action')
    if next_action == 'backup':
        await perform_backup(update, context)
        return MAIN_MENU
    elif next_action == 'send':
        await context.bot.send_message(chat_id=update.effective_chat.id, text="PIN verified. Who is the recipient (enter 0x address)?")
        return GET_RECIPIENT
    return MAIN_MENU

async def set_pin_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer(); await query.edit_message_text("Please enter a new 4-digit PIN.")
    return NEW_PIN

async def get_new_pin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    pin = update.message.text; await update.message.delete()
    if not (pin.isdigit() and len(pin) == 4):
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Invalid PIN. Please enter exactly 4 digits. Or /cancel.")
        return NEW_PIN
    context.user_data['new_pin'] = pin
    await context.bot.send_message(chat_id=update.effective_chat.id, text="Please enter your new PIN again to confirm.")
    return CONFIRM_NEW_PIN

async def get_pin_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    pin = update.message.text; await update.message.delete()
    if pin != context.user_data.get('new_pin'):
        await context.bot.send_message(chat_id=update.effective_chat.id, text="PINs do not match. Please start over.", reply_markup=get_settings_menu_keyboard())
        return SETTINGS_MENU
    pin_hash = hash_pin(pin, update.effective_user.id)
    users_col.update_one({"telegram_id": update.effective_user.id}, {"$set": {"pin_hash": pin_hash}})
    await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ PIN successfully set!", reply_markup=get_main_menu_keyboard())
    return MAIN_MENU

async def perform_backup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    mnemonic = decrypt_mnemonic(get_or_create_wallet(update.effective_user.id, "")['encrypted_mnemonic'], update.effective_user.id)
    warning = escape_markdown("🛑 *WARNING* 🛑\nAnyone with this phrase can steal your funds. Delete this message after saving.")
    await context.bot.send_message(chat_id=update.effective_chat.id, text=warning, parse_mode='MarkdownV2')
    await context.bot.send_message(chat_id=update.effective_chat.id, text=f"`{mnemonic}`", parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())

async def get_recipient(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['recipient'] = update.message.text; await update.message.reply_text("How much $BUNK?")
    return GET_AMOUNT

async def get_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        amount_str = update.message.text
        context.user_data['amount'] = float(amount_str)
        recipient, amount = context.user_data['recipient'], context.user_data['amount']
        FEE = 0.01
        text = f"*To:* `{escape_markdown(recipient)}`\n*Amount:* `{amount:.4f} $BUNK`\n*Fee:* `{FEE:.4f} $BUNK`\n*Total:* `{(amount+FEE):.4f} $BUNK`"
        keyboard = [[InlineKeyboardButton("✅ Confirm", callback_data="confirm_send"), InlineKeyboardButton("❌ Cancel", callback_data="cancel_send")]]
        await update.message.reply_text(text=f"Please confirm:\n\n{text}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='MarkdownV2')
        return CONFIRM_SEND
    except ValueError: await update.message.reply_text("Invalid amount. Cancelling."); return ConversationHandler.END

async def process_transaction(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    if query.data != "confirm_send":
        await query.edit_message_text(text="Transaction cancelled.", reply_markup=get_main_menu_keyboard())
        context.user_data.clear()
        return MAIN_MENU
    
    await query.edit_message_text(text="Broadcasting transaction to the network...")
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    sender_address = user_wallet['address']
    recipient, amount = context.user_data['recipient'], context.user_data['amount']
    FEE = "0.01"

    try:
        addr_info = requests.get(f"{BFF_API_URL}/address/{sender_address}")
        addr_info.raise_for_status()
        nonce = addr_info.json().get('nonce', 0)

        mnemonic = decrypt_mnemonic(user_wallet['encrypted_mnemonic'], update.effective_user.id)
        private_key = get_private_key_from_mnemonic(mnemonic)
        public_key = private_key.public_key

        tx_data = {'sender': sender_address, 'recipient': recipient, 'amount': str(amount), 'fee': FEE, 'nonce': nonce}
        tx_data_str = json.dumps(tx_data, sort_keys=True, separators=(',', ':')).encode()
        message_hash = hashlib.sha256(tx_data_str).digest()

        signature_obj = private_key.sign_msg_hash(message_hash)
        signature_hex = signature_obj.to_bytes().hex()
        public_key_hex = public_key.to_bytes().hex()

        payload = {**tx_data, 'public_key': public_key_hex, 'signature': signature_hex}
        
        response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload)
        response.raise_for_status()
        response_data = response.json()
        tx_id = response_data.get('transaction_id')
        
        amount_str = escape_markdown(f"{amount:.4f}")
        recipient_addr_str = escape_markdown(f"{recipient[:6]}...{recipient[-6:]}")
        explorer_url = f"https://explorer.bunknet.online/#/transaction/{tx_id}"
        result_message = (f"✅ *Transaction Successful*\n\n"
                          f"You sent `{amount_str} $BUNK` to `{recipient_addr_str}`.\n\n"
                          f"[View on Explorer]({explorer_url})")

    except requests.exceptions.RequestException as e:
        error_msg = "Could not send transaction."
        try: error_msg = e.response.json().get('error', error_msg)
        except: pass
        result_message = f"❌ *Transaction Failed*\n\n`{escape_markdown(error_msg)}`"
    
    await query.edit_message_text(text=result_message, reply_markup=get_main_menu_keyboard(), parse_mode='MarkdownV2', disable_web_page_preview=True)
    context.user_data.clear()
    return MAIN_MENU

# =============================================================================
# MAIN APPLICATION LOOP
# =============================================================================
def main() -> None:
    if not TELEGRAM_BOT_TOKEN or not BOT_SECRET_KEY:
        logging.error("Bot tokens and secret key must be set in the .env file."); return
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
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
            CONFIRM_SEND: [CallbackQueryHandler(process_transaction)]
        },
        fallbacks=[CommandHandler('start', start), CommandHandler('help', help_command), CommandHandler('cancel', cancel)],
        per_user=True, per_chat=True
    )
    application.add_handler(CommandHandler("address", receive))
    application.add_handler(conv_handler)
    
    logging.info("Bot is starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
    
