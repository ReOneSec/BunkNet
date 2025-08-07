import datetime
import hashlib
import json
import uuid
from os import environ
from urllib.parse import urlparse
from argparse import ArgumentParser
from functools import wraps
import time
import logging

import requests
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
from eth_keys.datatypes import PublicKey, Signature

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv()

# =============================================================================
# BunkNet Configuration
# =============================================================================
MONGO_URI = environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/?replicaSet=rs0')
ADMIN_SECRET_KEY = environ.get('BUNKNET_ADMIN_KEY', 'bunknet_super_admin_key')
P2P_SECRET_KEY = environ.get('BUNKNET_P2P_KEY', 'bunknet_super_secret_p2p_key')
MINER_ADDRESS = environ.get('BUNKNET_MINER_ADDRESS', '0x000000000000000000000000000000000000BEEF')
TREASURY_ADDRESS = environ.get('BUNKNET_TREASURY_ADDRESS')

# --- Tokenomics & Protocol Configuration ---
INITIAL_SUPPLY = 100000000.0
BASE_BLOCK_REWARD = 50.0
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
TARGET_BLOCK_TIME = 15 # Seconds

# =============================================================================
# Application & Database Setup
# =============================================================================
app = Flask(__name__)
CORS(app)

try:
    client = MongoClient(MONGO_URI)
    client.admin.command('ismaster')
    logging.info("MongoDB connection successful.")
except ConnectionFailure:
    logging.error("FATAL: Could not connect to MongoDB. Ensure it's running as a replica set.")
    exit()

db = client["bunknet_node"]
blocks_col = db["blocks"]
mempool_col = db["mempool"]
state_col = db["state"]
config_col = db["config"]

# =============================================================================
# Utility & Decorators
# =============================================================================
def prepare_json_response(data):
    def json_serial(obj):
        if isinstance(obj, (datetime.datetime, ObjectId)): return str(obj)
        raise TypeError(f"Type {type(obj)} not serializable")
    return json.loads(json.dumps(data, default=json_serial))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_key = request.headers.get('X-Admin-Key')
        if not ADMIN_SECRET_KEY or auth_key != ADMIN_SECRET_KEY:
            return jsonify({'error': 'Unauthorized: Admin key required'}), 401
        return f(*args, **kwargs)
    return decorated_function
    
def p2p_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_key = request.headers.get('X-P2P-Key')
        if not P2P_SECRET_KEY or auth_key != P2P_SECRET_KEY:
            return jsonify({'error': 'Unauthorized: P2P key required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def public_key_to_address(public_key: PublicKey) -> str:
    return public_key.to_checksum_address()

# =============================================================================
# Core Blockchain Class
# =============================================================================
class Blockchain:
    def __init__(self):
        self.nodes = set()
        if blocks_col.count_documents({}) == 0:
            logging.info("No existing blockchain found. Creating genesis block...")
            if not TREASURY_ADDRESS: raise ValueError("BUNKNET_TREASURY_ADDRESS must be set in .env")
            with client.start_session() as session:
                with session.start_transaction():
                    state_col.insert_one({'_id': TREASURY_ADDRESS, 'balance': INITIAL_SUPPLY, 'nonce': 0}, session=session)
                    genesis_tx = {'transaction_id': str(uuid.uuid4()),'sender': '0','recipient': TREASURY_ADDRESS,'amount': str(INITIAL_SUPPLY),'nonce': 0,'type': 'genesis_mint','timestamp': time.time()}
                    self.create_block(proof=1, previous_hash='0', transactions=[genesis_tx], session=session)
                    config_col.update_one({'_id': 'config'}, {'$set': {'difficulty_prefix': '0000'}}, upsert=True, session=session)
            logging.info("Genesis block and state created successfully.")

    def get_account_state(self, address, session=None):
        state = state_col.find_one({'_id': address}, session=session)
        return {'balance': state.get('balance', 0.0), 'nonce': state.get('nonce', 0)} if state else {'balance': 0.0, 'nonce': 0}

    def process_transactions(self, transactions, session=None):
        for tx in transactions:
            sender, recipient, amount_str = tx['sender'], tx['recipient'], tx['amount']
            amount = float(amount_str)
            fee = float(tx.get('fee', '0'))
            if sender != '0':
                sender_state = self.get_account_state(sender, session=session)
                new_sender_balance = sender_state['balance'] - amount - fee
                new_sender_nonce = sender_state['nonce'] + 1
                state_col.update_one({'_id': sender}, {'$set': {'balance': new_sender_balance, 'nonce': new_sender_nonce}}, upsert=True, session=session)
            recipient_state = self.get_account_state(recipient, session=session)
            new_recipient_balance = recipient_state['balance'] + amount
            state_col.update_one({'_id': recipient}, {'$set': {'balance': new_recipient_balance}}, upsert=True, session=session)

    def add_transaction_to_mempool(self, sender, recipient, amount, fee, nonce, signature, public_key):
        tx_data = {'sender': sender, 'recipient': recipient, 'amount': amount, 'fee': fee, 'nonce': nonce}
        is_valid, derived_pk = self.verify_signature(signature, tx_data)
        if not is_valid:
            return {'error': 'Invalid signature.'}
        if derived_pk.to_hex().lower() != public_key.lower():
             return {'error': 'Public key does not correspond to signature.'}
        derived_address = public_key_to_address(derived_pk)
        if sender.lower() != derived_address.lower():
            return {'error': 'Sender address does not match public key.'}
        account_state = self.get_account_state(sender)
        if int(nonce) != account_state['nonce']:
            return {'error': f"Invalid nonce. Expected {account_state['nonce']}, got {nonce}."}
        if account_state['balance'] < (float(amount) + float(fee)):
            return {'error': 'Insufficient funds.'}
        if mempool_col.find_one({'sender': sender, 'nonce': int(nonce)}):
            return {'error': 'Transaction with this nonce already in mempool.'}
        full_tx = {**tx_data, 'transaction_id': str(uuid.uuid4()), 'type': 'transfer', 'timestamp': time.time()}
        mempool_col.insert_one(full_tx)
        return full_tx

    @staticmethod
    def verify_signature(signature_hex, transaction_data):
        # This is the final, robust version of this function
        try:
            # The client sends a pure 130-char hex string, no '0x'
            signature_bytes = bytes.fromhex(signature_hex)

            # --- THE FINAL FIX: NORMALIZE THE 'v' VALUE ---
            # The last byte is the 'v' value.
            v = signature_bytes[64]
            # If v is 27 or 28 (legacy), normalize it to 0 or 1
            if v >= 27:
                normalized_v = v - 27
                # Reconstruct the signature with the normalized v
                normalized_signature_bytes = signature_bytes[:64] + bytes([normalized_v])
                sig = Signature(normalized_signature_bytes)
            else:
                # If v is already 0 or 1, use it as is
                sig = Signature(signature_bytes)
            
            tx_data_str = json.dumps(transaction_data, sort_keys=True, separators=(',', ':')).encode()
            message_hash = hashlib.sha256(tx_data_str).digest()

            recovered_pk = sig.recover_public_key_from_msg_hash(message_hash)
            return True, recovered_pk
        except Exception as e:
            logging.error(f"Signature verification failed: {e}")
            return False, None

    # --- Other Blockchain methods (no changes required) ---
    def mine_block(self):
        prev_block = self.get_previous_block()
        if not prev_block:
            logging.error("Could not find previous block to mine on top of.")
            return None
        proof = self.proof_of_work(prev_block['proof'])
        with client.start_session() as session:
            with session.start_transaction():
                try:
                    prev_block_in_session = self.get_previous_block(session=session)
                    mempool_txs = list(mempool_col.find({}, {'_id': 0}, session=session))
                    total_fees = sum(float(tx.get('fee', '0')) for tx in mempool_txs)
                    reward_tx = {'transaction_id': str(uuid.uuid4()),'sender': '0','recipient': MINER_ADDRESS,'amount': str(BASE_BLOCK_REWARD + total_fees),'nonce': -1,'type': 'reward','timestamp': time.time()}
                    transactions_to_process = mempool_txs + [reward_tx]
                    self.process_transactions(transactions_to_process, session=session)
                    block = self.create_block(proof, self.hash(prev_block_in_session), transactions_to_process, session=session)
                    mempool_col.delete_many({}, session=session)
                    self.adjust_difficulty(block, session=session)
                    logging.info(f"Block {block['index']} mined successfully and state committed.")
                    return block
                except Exception as e:
                    logging.error(f"ATOMIC MINE FAILED: Transaction aborted due to an error: {e}")
                    return None

    def adjust_difficulty(self, last_block, session=None):
        if last_block['index'] % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 or last_block['index'] <= 1: return
        prev_adjustment_block = blocks_col.find_one({'index': last_block['index'] - DIFFICULTY_ADJUSTMENT_INTERVAL}, session=session)
        if not prev_adjustment_block: return
        time_elapsed = last_block['timestamp'] - prev_adjustment_block['timestamp']
        expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME
        current_prefix = self.get_difficulty_prefix(session=session)
        if time_elapsed < expected_time / 1.5: new_prefix = current_prefix + '0'
        elif time_elapsed > expected_time * 1.5 and len(current_prefix) > 2: new_prefix = current_prefix[:-1]
        else: return
        logging.info(f"Adjusting difficulty from {len(current_prefix)} to {len(new_prefix)} zeros.")
        config_col.update_one({'_id': 'config'}, {'$set': {'difficulty_prefix': new_prefix}}, upsert=True, session=session)
    
    def get_difficulty_prefix(self, session=None):
        config = config_col.find_one({'_id': 'config'}, session=session)
        return config.get('difficulty_prefix', '0000') if config else '0000'

    def proof_of_work(self, previous_proof, session=None):
        new_proof = 1; difficulty_prefix = self.get_difficulty_prefix(session=session)
        while True:
            hash_op = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_op.startswith(difficulty_prefix): return new_proof
            new_proof += 1
            
    def create_block(self, proof, previous_hash, transactions, session=None):
        last_block = self.get_previous_block(session=session)
        index = last_block['index'] + 1 if last_block else 1
        block = {'index': index,'timestamp': time.time(),'proof': proof,'previous_hash': previous_hash,'transactions': transactions,'difficulty_prefix': self.get_difficulty_prefix(session=session)}
        block['hash'] = self.hash(block)
        blocks_col.insert_one(block, session=session)
        return block

    def get_previous_block(self, session=None):
        return blocks_col.find_one(sort=[("index", DESCENDING)], session=session)

    @staticmethod
    def hash(block):
        block_copy = block.copy(); block_copy.pop('hash', None)
        block_string = json.dumps(block_copy, sort_keys=True, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()
        
# =============================================================================
# Flask API Endpoints
# =============================================================================
blockchain = Blockchain()

@app.route('/new_transaction', methods=['POST'])
def new_transaction_endpoint():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'fee', 'nonce', 'signature', 'public_key']
    if not all(key in values for key in required): return jsonify({'error': 'Missing required fields'}), 400
    result = blockchain.add_transaction_to_mempool(**values)
    if 'error' in result: return jsonify(result), 400
    return jsonify({'message': 'Transaction added to mempool', 'transaction_id': result['transaction_id']}), 201

# --- Other endpoints (no changes required) ---
@app.route('/status', methods=['GET'])
def get_status():
    try:
        chain_length = blocks_col.count_documents({})
        pending_transactions = mempool_col.count_documents({})
        last_block = blockchain.get_previous_block()
        avg_block_time, hash_rate = 0, 0
        if last_block and chain_length > 10:
            recent_blocks = list(blocks_col.find({'index': {'$gt': chain_length - 10}}).sort("index", 1))
            if len(recent_blocks) > 1:
                time_diff = recent_blocks[-1]['timestamp'] - recent_blocks[0]['timestamp']
                avg_block_time = time_diff / (len(recent_blocks) - 1)
                difficulty_prefix = blockchain.get_difficulty_prefix()
                difficulty = 16**len(difficulty_prefix)
                hash_rate = difficulty / avg_block_time if avg_block_time > 0 else 0
        return jsonify({'chain_length': chain_length,'pending_transactions': pending_transactions,'last_block_hash': last_block['hash'] if last_block else '0','average_block_time': avg_block_time,'hash_rate': int(hash_rate)}), 200
    except Exception as e:
        logging.error(f"Error in /status endpoint: {e}")
        return jsonify({"error": "An internal error occurred."}), 500

@app.route('/get_chain', methods=['GET'])
def get_chain():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 0))
        query = blocks_col.find({}, {'_id': 0}).sort("index", DESCENDING)
        total = blocks_col.count_documents({})
        if limit > 0: query = query.skip((page - 1) * limit).limit(limit)
        return jsonify({'chain': prepare_json_response(list(query)), 'length': total}), 200
    except Exception as e:
        logging.error(f"Error in /get_chain endpoint: {e}")
        return jsonify({"error": "Could not retrieve chain data."}), 500

@app.route('/get_block/<identifier>', methods=['GET'])
def get_block(identifier):
    try:
        try: block = blocks_col.find_one({'index': int(identifier)})
        except ValueError: block = blocks_col.find_one({'hash': identifier})
        if block: return jsonify(prepare_json_response(block)), 200
        return jsonify({'error': 'Block not found'}), 404
    except Exception as e:
        logging.error(f"Error in /get_block endpoint: {e}")
        return jsonify({"error": "An internal error occurred."}), 500

@app.route('/mine_block', methods=['GET'])
def mine_block_endpoint():
    block = blockchain.mine_block()
    if block: return jsonify({'message': 'New Block Forged', 'block': prepare_json_response(block)}), 200
    return jsonify({'error': 'Mining failed and transaction was rolled back.'}), 500

@app.route('/address/<address>', methods=['GET'])
def get_address_details(address):
    state = blockchain.get_account_state(address)
    pipeline = [{"$unwind": "$transactions"},{"$match": {"$or": [{"transactions.sender": address}, {"transactions.recipient": address}]}}, {"$replaceRoot": {"newRoot": {"$mergeObjects": ["$transactions", {"block_index": "$index"}]}}}]
    transactions = list(blocks_col.aggregate(pipeline))
    return jsonify({'address': address,'balance': state['balance'],'nonce': state['nonce'],'transactions': prepare_json_response(transactions)}), 200

@app.route('/transaction/<tx_id>', methods=['GET'])
def get_transaction(tx_id):
    block = blocks_col.find_one({"transactions.transaction_id": tx_id}, {'_id': 0})
    if block:
        for tx in block['transactions']:
            if tx['transaction_id'] == tx_id: return jsonify(prepare_json_response({**tx, "block_index": block['index']})), 200
    tx_mempool = mempool_col.find_one({"transaction_id": tx_id}, {'_id': 0})
    if tx_mempool: return jsonify(prepare_json_response({**tx_mempool, "block_index": "Pending"})), 200
    return jsonify({"error": "Transaction not found"}), 404

@app.route('/get_mempool', methods=['GET'])
def get_mempool():
    mempool = list(mempool_col.find({}, {'_id': 0}))
    return jsonify({"mempool": mempool, "count": len(mempool)}), 200

@app.route('/admin/mint', methods=['POST'])
@admin_required
def admin_mint_tokens():
    values = request.get_json()
    recipient = values.get('recipient')
    amount = float(values.get('amount', 0))
    if not recipient or amount <= 0: return jsonify({'error': 'Recipient and a positive amount are required'}), 400
    mint_tx = {'transaction_id': str(uuid.uuid4()),'sender': '0','recipient': recipient,'amount': str(amount),'nonce': -1,'type': 'admin_mint','timestamp': time.time()}
    mempool_col.insert_one(mint_tx)
    logging.info(f"ADMIN: Minted {amount} $BUNK to {recipient}")
    return jsonify({'message': f'Mint transaction for {amount} $BUNK to {recipient} has been added to the mempool.'}), 201

@app.route('/admin/burn', methods=['POST'])
@admin_required
def admin_burn_tokens():
    values = request.get_json()
    sender = values.get('sender')
    amount = float(values.get('amount', 0))
    if not sender or amount <= 0: return jsonify({'error': 'Sender address and a positive amount are required'}), 400
    account_state = blockchain.get_account_state(sender)
    if account_state['balance'] < amount: return jsonify({'error': f'Insufficient funds. Address has {account_state["balance"]} $BUNK.'}), 400
    burn_tx = {'transaction_id': str(uuid.uuid4()),'sender': sender,'recipient': "0x000000000000000000000000000000000000dEaD",'amount': str(amount),'nonce': account_state['nonce'],'type': 'burn','fee': '0.0','timestamp': time.time()}
    mempool_col.insert_one(burn_tx)
    logging.info(f"ADMIN: Created burn transaction for {amount} $BUNK from {sender}")
    return jsonify({'message': f'Burn transaction for {amount} $BUNK from {sender} has been added to the mempool.'}), 201

# =============================================================================
# Main Execution
# =============================================================================
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    logging.info(f"Starting BunkNet node on port {args.port}")
    app.run(host='0.z0.0.0', port=args.port, debug=False)
                    
