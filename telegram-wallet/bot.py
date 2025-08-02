import logging
import os
import io
import qrcode
import binascii
import json
import hashlib

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

# --- Wallet & Crypto Helpers ---
def encrypt_mnemonic(mnemonic: str, user_id: int) -> str:
    """Encrypts a mnemonic using a key derived from the bot secret and user ID."""
    salt = get_random_bytes(16)
    password = f"{BOT_SECRET_KEY}{user_id}"
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(mnemonic.encode(), AES.block_size))
    return binascii.hexlify(salt + cipher.iv + encrypted).decode()

def decrypt_mnemonic(encrypted_hex: str, user_id: int) -> str:
    """Decrypts a mnemonic."""
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    salt = encrypted_bytes[:16]
    iv = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
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
    """Retrieves an existing user wallet or creates a new one."""
    user = users_col.find_one({"telegram_id": user_id})
    if user:
        return user
    
    mnemonic = mnemo.generate(strength=128)
    _, public_key = get_keys_from_mnemonic(mnemonic)
    encrypted_mnemonic = encrypt_mnemonic(mnemonic, user_id)
    
    new_user = {
        "telegram_id": user_id,
        "username": username,
        "public_key": public_key,
        "encrypted_mnemonic": encrypted_mnemonic,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    users_col.insert_one(new_user)
    logging.info(f"Created a new wallet for user {username} ({user_id})")
    return new_user

# --- Main Menu & UI ---
def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton("💰 Balance", callback_data="balance"), InlineKeyboardButton("📜 History", callback_data="history")],
        [InlineKeyboardButton("⬆️ Send", callback_data="send"), InlineKeyboardButton("⬇️ Receive", callback_data="receive")],
    ]
    return InlineKeyboardMarkup(keyboard)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /start command."""
    user = update.effective_user
    get_or_create_wallet(user.id, user.username)
    
    await update.message.reply_text(
        f"👋 Welcome to the BunkNet Wallet, {user.first_name}!\n\n"
        "You can manage your $BUNK tokens right here. Use the buttons below to navigate.",
        reply_markup=get_main_menu_keyboard()
    )

async def main_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles all button presses from the main menu."""
    query = update.callback_query
    await query.answer()
    
    actions = {
        'balance': balance,
        'history': history,
        'send': send_start,
        'receive': receive,
    }
    
    action = actions.get(query.data)
    if action:
        # Pass the original update object to the action handler
        await action(update, context)

# --- Command Handlers ---
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Shows the user's balance."""
    user_id = update.effective_user.id
    user_wallet = get_or_create_wallet(user_id, update.effective_user.username)
    public_key = user_wallet['public_key']
    
    try:
        response = requests.get(f"{BFF_API_URL}/address/{public_key}")
        response.raise_for_status()
        data = response.json()
        balance_val = data.get('balance', 0)
        message = f"Your current balance is:\n\n`{balance_val:.4f}` *$BUNK*"
    except requests.exceptions.RequestException:
        message = "Could not connect to the BunkNet network. Please try again later."
    
    await context.bot.send_message(chat_id=user_id, text=message, parse_mode='MarkdownV2')

async def receive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Shows the user's address and QR code."""
    user_id = update.effective_user.id
    user_wallet = get_or_create_wallet(user_id, update.effective_user.username)
    public_key = user_wallet['public_key']
    
    qr_img = qrcode.make(public_key)
    bio = io.BytesIO()
    qr_img.save(bio, 'PNG')
    bio.seek(0)
    
    caption = f"Here is your BunkNet address to receive `$BUNK`:\n\n`{public_key}`"
    await context.bot.send_photo(chat_id=user_id, photo=bio, caption=caption, parse_mode='MarkdownV2')

async def history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Shows the user's transaction history."""
    user_id = update.effective_user.id
    user_wallet = get_or_create_wallet(user_id, update.effective_user.username)
    public_key = user_wallet['public_key']
    
    try:
        response = requests.get(f"{BFF_API_URL}/address/{public_key}")
        response.raise_for_status()
        data = response.json()
        transactions = data.get('transactions', [])
        
        if not transactions:
            message = "You have no transactions yet."
        else:
            message = "📜 *Your recent transactions:*\n\n"
            for tx in reversed(transactions[-5:]): # Show last 5
                direction = "➡ Sent" if tx['sender'] == public_key else "⬅ Received"
                amount = tx['amount']
                other_party = tx['recipient' if direction == "➡ Sent" else 'sender']
                message += f"`{direction}` `{amount:.2f} $BUNK`\n*To/From:* `{other_party[:10]}...`\n\n"
    except requests.exceptions.RequestException:
        message = "Could not fetch transaction history. Please try again later."
        
    await context.bot.send_message(chat_id=user_id, text=message, parse_mode='MarkdownV2')

# --- Send Conversation ---
RECIPIENT, AMOUNT, FEE, CONFIRMATION = range(4)

async def send_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Starts the send conversation."""
    await context.bot.send_message(chat_id=update.effective_user.id, text="Who is the recipient? Please paste their BunkNet address.")
    return RECIPIENT

async def get_recipient(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores recipient and asks for amount."""
    context.user_data['recipient'] = update.message.text
    await update.message.reply_text("How much $BUNK would you like to send?")
    return AMOUNT

async def get_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores amount and asks for fee."""
    try:
        context.user_data['amount'] = float(update.message.text)
        await update.message.reply_text("What transaction fee would you like to include? (e.g., 0.01)")
        return FEE
    except ValueError:
        await update.message.reply_text("Invalid amount. Please enter a number. Cancelling transaction.")
        return ConversationHandler.END

async def get_fee_and_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores fee and asks for confirmation."""
    try:
        context.user_data['fee'] = float(update.message.text)
        recipient = context.user_data['recipient']
        amount = context.user_data['amount']
        fee = context.user_data['fee']
        
        confirmation_text = (
            f"Please confirm the transaction:\n\n"
            f"*To:* `{recipient}`\n"
            f"*Amount:* `{amount:.4f} $BUNK`\n"
            f"*Fee:* `{fee:.4f} $BUNK`\n\n"
            f"*Total Debit:* `{(amount + fee):.4f} $BUNK`"
        )
        keyboard = [[InlineKeyboardButton("✅ Confirm & Send", callback_data="confirm_send"), InlineKeyboardButton("❌ Cancel", callback_data="cancel_send")]]
        await update.message.reply_text(text=confirmation_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='MarkdownV2')
        return CONFIRMATION
    except ValueError:
        await update.message.reply_text("Invalid fee. Please enter a number. Cancelling transaction.")
        return ConversationHandler.END

async def process_transaction(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Finalizes and sends the transaction."""
    query = update.callback_query
    await query.answer()
    
    if query.data == "confirm_send":
        await query.edit_message_text(text="Sending transaction...")
        
        user_id = update.effective_user.id
        user_wallet = get_or_create_wallet(user_id, update.effective_user.username)
        
        mnemonic = decrypt_mnemonic(user_wallet['encrypted_mnemonic'], user_id)
        private_key, public_key = get_keys_from_mnemonic(mnemonic)
        
        tx_data = {
            'sender': public_key,
            'recipient': context.user_data['recipient'],
            'amount': context.user_data['amount'],
            'fee': context.user_data['fee']
        }
        
        tx_data_str = json.dumps(tx_data, sort_keys=True)
        tx_hash = hashlib.sha256(tx_data_str.encode()).digest()
        signature = binascii.hexlify(private_key.sign(tx_hash)).decode()

        payload = {**tx_data, 'public_key': public_key, 'signature': signature}
        
        try:
            response = requests.post(f"{BFF_API_URL}/new_transaction", json=payload)
            response.raise_for_status()
            result_message = "✅ Transaction sent successfully! It will be processed in the next block."
        except requests.exceptions.RequestException as e:
            result_message = f"❌ Error: {e.response.json().get('error', 'Could not send transaction.')}"

        await query.edit_message_text(text=result_message)
        
    else:
        await query.edit_message_text(text="Transaction cancelled.")
        
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancels and ends the conversation."""
    await update.message.reply_text("Transaction cancelled.")
    return ConversationHandler.END


def main() -> None:
    """Start the bot."""
    if not TELEGRAM_BOT_TOKEN or not BOT_SECRET_KEY:
        logging.error("TELEGRAM_BOT_TOKEN and BOT_SECRET_KEY must be set in .env file.")
        return
        
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    send_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(send_start, pattern='^send$')],
        states={
            RECIPIENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_recipient)],
            AMOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_amount)],
            FEE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_fee_and_confirm)],
            CONFIRMATION: [CallbackQueryHandler(process_transaction, pattern='^confirm_send$|^cancel_send$')]
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(main_menu_callback, pattern='^(?!send|confirm_send|cancel_send).*$'))
    application.add_handler(send_conv_handler)

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
  
