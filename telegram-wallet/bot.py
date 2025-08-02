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
from ecdsa import SECP256k1, SigningKey
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from pymongo import MongoClient

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, MessageHandler,
    ConversationHandler, ContextTypes, filters
)

# --- Load Configuration ---
load_dotenv()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
BOT_SECRET_KEY = os.environ.get("BOT_SECRET_KEY")
BFF_API_URL = os.environ.get("BUNKNET_BFF_API_URL", "http://localhost:7000/api")
MONGO_URI = os.environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/')

# --- Setup ---
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

client = MongoClient(MONGO_URI)
db = client["bunknet_telegram_bot"]
users_col = db["users"]

mnemo = Mnemonic("english")

# --- State Constants for Conversations ---
SET_PIN, CONFIRM_PIN, VERIFY_PIN = range(3)
RECIPIENT, AMOUNT, FEE, CONFIRMATION = range(4)

# --- Helper Functions ---
def escape_markdown(text: str) -> str:
    """Escapes special characters for Telegram's MarkdownV2."""
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)

def hash_pin(pin: str, user_id: int) -> str:
    salt = str(user_id).encode()
    return hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000, 64).hex()

# --- Wallet & Crypto Helpers ---
def encrypt_mnemonic(mnemonic: str, user_id: int) -> str:
    salt = get_random_bytes(16)
    password = f"{BOT_SECRET_KEY}{user_id}"
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(mnemonic.encode(), AES.block_size))
    return binascii.hexlify(salt + cipher.iv + encrypted).decode()
def decrypt_mnemonic(encrypted_hex: str, user_id: int) -> str:
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    salt, iv, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    password = f"{BOT_SECRET_KEY}{user_id}"
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
def get_keys_from_mnemonic(mnemonic: str) -> tuple[SigningKey, str]:
    seed = Mnemonic.to_seed(mnemonic)
    private_key = SigningKey.from_string(seed[:32], curve=SECP256k1)
    public_key = binascii.hexlify(private_key.get_verifying_key().to_string()).decode()
    return private_key, public_key
def get_or_create_wallet(user_id: int, username: str) -> dict:
    user = users_col.find_one({"telegram_id": user_id})
    if user: return user
    mnemonic = mnemo.generate(strength=128)
    _, public_key = get_keys_from_mnemonic(mnemonic)
    encrypted_mnemonic = encrypt_mnemonic(mnemonic, user_id)
    new_user = {"telegram_id": user_id, "username": username, "public_key": public_key, "encrypted_mnemonic": encrypted_mnemonic, "created_at": datetime.datetime.now(datetime.timezone.utc), "pin_hash": None}
    users_col.insert_one(new_user)
    logging.info(f"Created a new wallet for user {username} ({user_id})")
    return new_user

# --- UI Keyboards ---
def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [[InlineKeyboardButton("💰 Balance", callback_data="balance"), InlineKeyboardButton("📜 History", callback_data="history")], [InlineKeyboardButton("⬆️ Send", callback_data="send"), InlineKeyboardButton("⬇️ Receive", callback_data="receive")], [InlineKeyboardButton("⚙️ Settings", callback_data="settings")]]
    return InlineKeyboardMarkup(keyboard)
def get_settings_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [[InlineKeyboardButton("🔑 Set/Change PIN", callback_data="set_pin")], [InlineKeyboardButton("📄 View Seed Phrase", callback_data="backup")], [InlineKeyboardButton("« Back to Main Menu", callback_data="main_menu")]]
    return InlineKeyboardMarkup(keyboard)

# --- Top Level Command Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    get_or_create_wallet(user.id, user.username)
    await update.message.reply_text(f"👋 Welcome to the BunkNet Wallet, {user.first_name}!\n\nUse the buttons below or type /help for a list of commands.", reply_markup=get_main_menu_keyboard())
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = r"""
*BunkNet Wallet Bot Help*

Here are the available commands:

`/start` \- Initializes the bot and shows the main menu\.
`/address` \- Shows your wallet address and QR code\.
`/help` \- Shows this help message\.
`/cancel` \- Cancels any ongoing operation \(like sending or setting a PIN\)\.

You can also use the interactive buttons to navigate\.
"""
    await update.message.reply_text(help_text, parse_mode='MarkdownV2')
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Action cancelled.", reply_markup=get_main_menu_keyboard())
    return ConversationHandler.END

# --- Simple Button Actions ---
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query; await query.answer()
    user_wallet = get_or_create_wallet(update.effective_user.id, update.effective_user.username)
    try:
        response = requests.get(f"{BFF_API_URL}/address/{user_wallet['public_key']}")
        response.raise_for_status()
        balance_val = response.json().get('balance', 0)
        balance_str = escape_markdown(f"{balance_val:.4f}")
        message = f"Your current balance is:\n\n`{balance_str}` *$BUNK*"
    except requests.exceptions.RequestException: message = "Could not connect to the BunkNet network."
    await query.edit_message_text(text=message, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
async def receive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query; await query.answer()
    await query.message.delete()
    user_wallet = get_or_create_wallet(update.effective_user.id, update.effective_user.username)
    qr_img = qrcode.make(user_wallet['public_key']); bio = io.BytesIO(); qr_img.save(bio, 'PNG'); bio.seek(0)
    caption = f"Here is your BunkNet address:\n\n`{user_wallet['public_key']}`"
    await context.bot.send_photo(chat_id=update.effective_user.id, photo=bio, caption=caption, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
async def history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query; await query.answer()
    user_wallet = get_or_create_wallet(update.effective_user.id, update.effective_user.username)
    try:
        response = requests.get(f"{BFF_API_URL}/address/{user_wallet['public_key']}")
        response.raise_for_status()
        transactions = response.json().get('transactions', [])
        if not transactions: message = "You have no transactions yet."
        else:
            message_parts = ["📜 *Your recent transactions:*\n"]
            for tx in reversed(transactions[-5:]):
                direction = "➡ Sent" if tx['sender'] == user_wallet['public_key'] else "⬅ Received"
                amount_str = escape_markdown(f"{tx['amount']:.2f}")
                other_party = tx['recipient'] if direction == "➡ Sent" else tx['sender']
                message_parts.append(f"`{direction}` `{amount_str} $BUNK`\n*To/From:* `{other_party[:10]}...`\n")
            message = "\n".join(message_parts)
    except requests.exceptions.RequestException: message = "Could not fetch transaction history."
    await query.edit_message_text(text=message, parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
async def settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query; await query.answer()
    await query.edit_message_text("⚙️ Settings", reply_markup=get_settings_menu_keyboard())
async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query; await query.answer()
    await query.edit_message_text("Main Menu:", reply_markup=get_main_menu_keyboard())

# --- Set PIN Conversation ---
async def set_pin_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer(); await query.edit_message_text("Please enter a new 4-digit PIN.")
    return SET_PIN
async def get_new_pin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    pin = update.message.text
    if not (pin.isdigit() and len(pin) == 4):
        await update.message.reply_text("Invalid PIN. Please enter exactly 4 digits. Or /cancel.")
        return SET_PIN
    context.user_data['new_pin'] = pin
    await update.message.reply_text("Please enter your new PIN again to confirm.")
    return CONFIRM_PIN
async def get_pin_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    pin = update.message.text
    if pin != context.user_data['new_pin']:
        await update.message.reply_text("PINs do not match. Please start over.", reply_markup=get_settings_menu_keyboard())
        return ConversationHandler.END
    pin_hash = hash_pin(pin, update.effective_user.id)
    users_col.update_one({"telegram_id": update.effective_user.id}, {"$set": {"pin_hash": pin_hash}})
    await update.message.reply_text("✅ PIN successfully set!", reply_markup=get_main_menu_keyboard())
    return ConversationHandler.END

# --- Send & Backup Conversations (PIN Protected) ---
async def protected_action_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    user_wallet = get_or_create_wallet(query.from_user.id, "")
    if not user_wallet.get('pin_hash'):
        await query.edit_message_text("Please set a PIN in Settings first.", reply_markup=get_settings_menu_keyboard())
        return ConversationHandler.END
    context.user_data['next_action'] = query.data
    await query.edit_message_text(f"Please enter your PIN to authorize this action.")
    return VERIFY_PIN
async def check_pin_and_proceed(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    pin = update.message.text
    user_wallet = get_or_create_wallet(update.effective_user.id, "")
    if hash_pin(pin, update.effective_user.id) != user_wallet.get('pin_hash'):
        await update.message.reply_text("❌ Incorrect PIN. Action cancelled.", reply_markup=get_main_menu_keyboard())
        return ConversationHandler.END
    next_action = context.user_data.get('next_action')
    if next_action == 'backup':
        await perform_backup(update, context); return ConversationHandler.END
    elif next_action == 'send':
        await update.message.reply_text("PIN verified. Who is the recipient?"); return RECIPIENT
    return ConversationHandler.END
async def perform_backup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    mnemonic = decrypt_mnemonic(get_or_create_wallet(update.effective_user.id, "")['encrypted_mnemonic'], update.effective_user.id)
    warning_text = escape_markdown("🛑 *WARNING: SENSITIVE INFORMATION* 🛑\nAnyone with this phrase can steal your funds. Delete this message after you've saved it.")
    await update.message.reply_text(warning_text, parse_mode='MarkdownV2')
    await update.message.reply_text(f"`{mnemonic}`", parse_mode='MarkdownV2', reply_markup=get_main_menu_keyboard())
async def get_recipient(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['recipient'] = update.message.text; await update.message.reply_text("How much $BUNK?")
    return AMOUNT
async def get_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try: context.user_data['amount'] = float(update.message.text); await update.message.reply_text("Transaction fee? (e.g., 0.01)")
    except ValueError: await update.message.reply_text("Invalid amount. Cancelling."); return ConversationHandler.END
    return FEE
async def get_fee_and_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        context.user_data['fee'] = float(update.message.text)
        recipient, amount, fee = context.user_data['recipient'], context.user_data['amount'], context.user_data['fee']
        amount_s, fee_s, total_s = escape_markdown(f"{amount:.4f}"), escape_markdown(f"{fee:.4f}"), escape_markdown(f"{(amount + fee):.4f}")
        text = f"*To:* `{recipient}`\n*Amount:* `{amount_s} $BUNK`\n*Fee:* `{fee_s} $BUNK`\n\n*Total Debit:* `{total_s} $BUNK`"
        keyboard = [[InlineKeyboardButton("✅ Confirm & Send", callback_data="confirm_send"), InlineKeyboardButton("❌ Cancel", callback_data="cancel_send")]]
        await update.message.reply_text(text=f"Please confirm:\n\n{text}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='MarkdownV2')
        return CONFIRMATION
    except ValueError: await update.message.reply_text("Invalid fee. Cancelling."); return ConversationHandler.END
async def process_transaction(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query; await query.answer()
    if query.data == "confirm_send":
        await query.edit_message_text(text="Sending transaction...")
        user_wallet = get_or_create_wallet(update.effective_user.id, "")
        mnemonic = decrypt_mnemonic(user_wallet['encrypted_mnemonic'], update.effective_user.id)
        private_key, public_key = get_keys_from_mnemonic(mnemonic)
        tx_data = {'sender': public_key, 'recipient': context.user_data['recipient'], 'amount': context.user_data['amount'], 'fee': context.user_data['fee']}
        tx_hash = hashlib.sha256(json.dumps({k: tx_data[k] for k in ['sender', 'recipient', 'amount', 'fee']}, sort_keys=True).encode()).digest()
        signature = binascii.hexlify(private_key.sign(tx_hash)).decode()
        payload = {**tx_data, 'public_key': public_key, 'signature': signature}
        try:
            response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload); response.raise_for_status()
            result_message = "✅ Transaction sent successfully! It will be processed in the next block."
        except requests.exceptions.RequestException as e: result_message = f"❌ Error: {e.response.json().get('error', 'Could not send transaction.')}"
        await query.edit_message_text(text=result_message, reply_markup=get_main_menu_keyboard())
    else:
        await query.edit_message_text(text="Transaction cancelled.", reply_markup=get_main_menu_keyboard())
    return ConversationHandler.END

def main() -> None:
    if not TELEGRAM_BOT_TOKEN or not BOT_SECRET_KEY: logging.error("Bot tokens must be set in .env file."); return
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).job_queue(None).build()

    set_pin_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(set_pin_start, pattern='^set_pin$')],
        states={ SET_PIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_new_pin)], CONFIRM_PIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_pin_confirmation)]},
        fallbacks=[CommandHandler('cancel', cancel)],
    )
    send_and_backup_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(protected_action_start, pattern='^(send|backup)$')],
        states={
            VERIFY_PIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_pin_and_proceed)],
            RECIPIENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_recipient)],
            AMOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_amount)],
            FEE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_fee_and_confirm)],
            CONFIRMATION: [CallbackQueryHandler(process_transaction)]
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("address", receive))
    application.add_handler(CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$'))
    application.add_handler(CallbackQueryHandler(settings, pattern='^settings$'))
    application.add_handler(CallbackQueryHandler(balance, pattern='^balance$'))
    application.add_handler(CallbackQueryHandler(history, pattern='^history$'))
    application.add_handler(CallbackQueryHandler(receive, pattern='^receive$'))
    application.add_handler(set_pin_handler)
    application.add_handler(send_and_backup_handler)

    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
                  
