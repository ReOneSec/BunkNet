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

import binascii
import ecdsa
import requests
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
from Crypto.Hash import keccak
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Load environment variables ---
load_dotenv()

# =============================================================================
# BunkNet Configuration
# =============================================================================
MONGO_URI = environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/?replicaSet=rs0')
ADMIN_SECRET_KEY = environ.get('BUNKNET_ADMIN_KEY', 'bunknet_super_admin_key')
P2P_SECRET_KEY = environ.get('BUNKNET_P2P_KEY', 'bunknet_super_secret_p2p_key')

MINER_ADDRESS = environ.get('BUNKNET_MINER_ADDRESS', '0x000000000000000000000000000000000000BEEF')
TREASURY_ADDRESS = environ.get('BUNKNET_TREASURY_ADDRESS')
FAUCET_ADDRESS = environ.get('BUNKNET_FAUCET_ADDRESS')
FAUCET_SEED = environ.get('BUNKNET_FAUCET_SEED')

# --- Tokenomics & Protocol Configuration ---
INITIAL_SUPPLY = 100000000.0
BASE_BLOCK_REWARD = 50.0
FAUCET_DRIP_AMOUNT = 10.0
FAUCET_COOLDOWN_HOURS = 24
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
faucet_requests_col = db["faucet_requests"]
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

def public_key_to_address(verifying_key: ecdsa.VerifyingKey) -> str:
    public_key_bytes = verifying_key.to_string("uncompressed")[1:]
    k = keccak.new(digest_bits=256); k.update(public_key_bytes)
    return '0x' + k.digest()[-20:].hex()

# --- Faucet Wallet Setup ---
faucet_private_key, FAUCET_PUBLIC_KEY = None, None
if FAUCET_SEED:
    try:
        seed_bytes = Bip39SeedGenerator(FAUCET_SEED).Generate()
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        private_key_bytes = bip44_acc_ctx.PrivateKey().Raw().ToBytes()
        faucet_private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        faucet_verifying_key = faucet_private_key.get_verifying_key()
        FAUCET_PUBLIC_KEY = binascii.hexlify(faucet_verifying_key.to_string()).decode()
        derived_faucet_address = public_key_to_address(faucet_verifying_key)

        if FAUCET_ADDRESS and FAUCET_ADDRESS.lower() != derived_faucet_address.lower():
            logging.error("FATAL: FAUCET_ADDRESS in .env does not match address from BUNKNET_FAUCET_SEED.")
            exit()
        elif not FAUCET_ADDRESS:
            FAUCET_ADDRESS = derived_faucet_address
            logging.warning(f"BUNKNET_FAUCET_ADDRESS not set. Using derived address: {FAUCET_ADDRESS}")
    except Exception as e:
        logging.error(f"FATAL: Could not initialize faucet wallet. Error: {e}"); exit()
else:
    logging.warning("BUNKNET_FAUCET_SEED not found. Faucet will be disabled.")

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
                    genesis_tx = {'transaction_id': str(uuid.uuid4()),'sender': '0','recipient': TREASURY_ADDRESS,'amount': INITIAL_SUPPLY,'nonce': 0,'type': 'genesis_mint','timestamp': time.time()}
                    self.create_block(proof=1, previous_hash='0', transactions=[genesis_tx], session=session)
                    config_col.update_one({'_id': 'config'}, {'$set': {'difficulty_prefix': '0000'}}, upsert=True, session=session)
            logging.info("Genesis block and state created successfully.")

    # --- THE FIX: All methods below are now correctly indented inside the Blockchain class ---

    def get_account_state(self, address, session=None):
        state = state_col.find_one({'_id': address}, session=session)
        return {'balance': state.get('balance', 0.0), 'nonce': state.get('nonce', 0)} if state else {'balance': 0.0, 'nonce': 0}

    def process_transactions(self, transactions, session=None):
        for tx in transactions:
            sender, recipient, amount = tx['sender'], tx['recipient'], tx['amount']
            if sender != '0':
                sender_state = self.get_account_state(sender, session=session)
                new_sender_balance = sender_state['balance'] - amount - tx.get('fee', 0)
                new_sender_nonce = sender_state['nonce'] + 1
                state_col.update_one({'_id': sender}, {'$set': {'balance': new_sender_balance, 'nonce': new_sender_nonce}}, upsert=True, session=session)
            recipient_state = self.get_account_state(recipient, session=session)
            new_recipient_balance = recipient_state['balance'] + amount
            state_col.update_one({'_id': recipient}, {'$set': {'balance': new_recipient_balance}}, upsert=True, session=session)

    def add_transaction_to_mempool(self, sender, recipient, amount, fee, nonce, signature, public_key):
        if not (sender.startswith('0x') and len(sender) == 42): return {'error': 'Invalid sender address format.'}
        tx_data = {'sender': sender, 'recipient': recipient, 'amount': float(amount), 'fee': float(fee), 'nonce': int(nonce)}
        if not self.verify_signature(public_key, signature, tx_data): return {'error': 'Invalid signature.'}
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        if sender != public_key_to_address(vk): return {'error': 'Sender address does not match public key.'}
        account_state = self.get_account_state(sender)
        if int(nonce) != account_state['nonce']: return {'error': f"Invalid nonce. Expected {account_state['nonce']}, got {nonce}."}
        if account_state['balance'] < (float(amount) + float(fee)): return {'error': 'Insufficient funds.'}
        if mempool_col.find_one({'sender': sender, 'nonce': int(nonce)}): return {'error': 'Transaction with this nonce already in mempool.'}
        full_tx = {**tx_data, 'transaction_id': str(uuid.uuid4()), 'type': 'transfer', 'timestamp': time.time(), 'signature': signature, 'public_key': public_key}
        mempool_col.insert_one(full_tx)
        return full_tx

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
                    total_fees = sum(tx.get('fee', 0) for tx in mempool_txs)
                    reward_tx = {'transaction_id': str(uuid.uuid4()),'sender': '0','recipient': MINER_ADDRESS,'amount': BASE_BLOCK_REWARD + total_fees,'nonce': -1,'type': 'reward','timestamp': time.time()}
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
            
@staticmethod
def verify_signature(public_key_hex, signature_hex, transaction_data):
    try:
        # THE FIX: Ensure we use the 64-byte (128 hex chars) public key for verification.
        if public_key_hex.startswith('04'):
            public_key_hex = public_key_hex[2:]

        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
        
        tx_data_str = json.dumps(transaction_data, sort_keys=True).encode()
        tx_hash = hashlib.sha256(tx_data_str).digest()
        
        return vk.verify(bytes.fromhex(signature_hex), tx_hash)
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False

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

    @staticmethod
    def is_chain_valid(chain):
        previous_block = chain[0]; i = 1
        while i < len(chain):
            block = chain[i]
            if block['previous_hash'] != Blockchain.hash(previous_block): return False
            proof, previous_proof = block['proof'], previous_block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if not hash_operation.startswith(block.get('difficulty_prefix', '0000')): return False
            previous_block = block; i += 1
        return True

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc or parsed_url.path)

    def resolve_conflicts(self):
        neighbours = self.nodes; new_chain = None
        max_length = blocks_col.count_documents({})
        for node in neighbours:
            try:
                headers = {'X-P2P-Key': P2P_SECRET_KEY}
                response = requests.get(f'http://{node}/get_chain', headers=headers, timeout=5)
                if response.status_code == 200:
                    length, chain = response.json()['length'], response.json()['chain']
                    if length > max_length and self.is_chain_valid(chain):
                        max_length, new_chain = length, chain
            except requests.exceptions.RequestException: continue
        if new_chain:
            logging.info("Found a longer valid chain. Atomically rebuilding local state...")
            with client.start_session() as session:
                with session.start_transaction():
                    blocks_col.delete_many({}, session=session)
                    blocks_col.insert_many(new_chain, session=session)
                    state_col.delete_many({}, session=session)
                    mempool_col.delete_many({}, session=session)
                    logging.info("Re-processing transactions to rebuild the world state...")
                    all_blocks = list(blocks_col.find(sort=[("index", 1)], session=session))
                    for block in all_blocks: self.process_transactions(block['transactions'], session=session)
            logging.info("State rebuild complete. Chain is now authoritative.")
            return True
        logging.info("Our chain is authoritative.")
        return False
        
# =============================================================================
# Flask API Endpoints
# =============================================================================
blockchain = Blockchain()

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

@app.route('/new_transaction', methods=['POST'])
def new_transaction_endpoint():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'fee', 'nonce', 'signature', 'public_key']
    if not all(key in values for key in required): return jsonify({'error': 'Missing required fields'}), 400
    result = blockchain.add_transaction_to_mempool(**values)
    if 'error' in result: return jsonify(result), 400
    return jsonify({'message': 'Transaction added to mempool', 'transaction_id': result['transaction_id']}), 201

@app.route('/get_mempool', methods=['GET'])
def get_mempool():
    mempool = list(mempool_col.find({}, {'_id': 0}))
    return jsonify({"mempool": mempool, "count": len(mempool)}), 200
    
@app.route('/faucet/drip', methods=['POST'])
def faucet_drip_endpoint():
    if not faucet_private_key: return jsonify({'error': 'Faucet is not configured.'}), 501
    recipient = request.get_json().get('recipient')
    if not recipient: return jsonify({'error': 'Recipient address is required.'}), 400
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    cooldown = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=FAUCET_COOLDOWN_HOURS)
    if faucet_requests_col.find_one({"ip_address": client_ip, "timestamp": {"$gte": cooldown}}):
        return jsonify({'error': f'This IP has received funds within the last {FAUCET_COOLDOWN_HOURS} hours.'}), 429
    faucet_state = blockchain.get_account_state(FAUCET_ADDRESS)
    if faucet_state['balance'] < FAUCET_DRIP_AMOUNT: return jsonify({'error': 'Faucet is empty.'}), 503
    nonce = faucet_state['nonce']
    tx_data = {'sender': FAUCET_ADDRESS,'recipient': recipient,'amount': FAUCET_DRIP_AMOUNT,'fee': 0.0,'nonce': nonce}
    tx_hash = hashlib.sha256(json.dumps(tx_data, sort_keys=True).encode()).digest()
    signature = binascii.hexlify(faucet_private_key.sign(tx_hash)).decode()
    result = blockchain.add_transaction_to_mempool(sender=FAUCET_ADDRESS,recipient=recipient,amount=FAUCET_DRIP_AMOUNT,fee=0.0,nonce=nonce,signature=signature,public_key=FAUCET_PUBLIC_KEY)
    if 'error' in result: return jsonify(result), 500
    faucet_requests_col.insert_one({"ip_address": client_ip, "address": recipient, "timestamp": datetime.datetime.now(datetime.timezone.utc)})
    return jsonify({'message': f'Sent {FAUCET_DRIP_AMOUNT} $BUNK.', 'transaction_id': result['transaction_id']}), 201
    
# --- P2P Networking Endpoints ---
@app.route('/nodes/register', methods=['POST'])
@p2p_required
def register_nodes():
    nodes = request.get_json().get('nodes')
    if nodes is None: return "Error: Please supply a valid list of nodes", 400
    for node in nodes: blockchain.add_node(node)
    return jsonify({'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
@p2p_required
def consensus():
    replaced = blockchain.resolve_conflicts()
    message = 'Our chain was replaced' if replaced else 'Our chain is authoritative'
    return jsonify({'message': message}), 200

# --- Admin Endpoints ---
@app.route('/admin/mint', methods=['POST'])
@admin_required
def admin_mint_tokens():
    values = request.get_json()
    recipient = values.get('recipient')
    amount = float(values.get('amount', 0))
    if not recipient or amount <= 0:
        return jsonify({'error': 'Recipient and a positive amount are required'}), 400
    
    mint_tx = {
        'transaction_id': str(uuid.uuid4()), 'sender': '0', 'recipient': recipient, 'amount': amount,
        'nonce': -1, 'type': 'admin_mint', 'timestamp': time.time()
    }
    mempool_col.insert_one(mint_tx)
    logging.info(f"ADMIN: Minted {amount} $BUNK to {recipient}")
    return jsonify({'message': f'Mint transaction for {amount} $BUNK to {recipient} has been added to the mempool.'}), 201

@app.route('/admin/burn', methods=['POST'])
@admin_required
def admin_burn_tokens():
    # This is a simplified burn. A real one would need a signature.
    values = request.get_json()
    sender = values.get('sender')
    amount = float(values.get('amount', 0))

    if not sender or amount <= 0:
        return jsonify({'error': 'Sender address and a positive amount are required'}), 400

    account_state = blockchain.get_account_state(sender)
    if account_state['balance'] < amount:
        return jsonify({'error': f'Insufficient funds to burn. Address has {account_state["balance"]} $BUNK.'}), 400

    # We create an unsigned transaction to the burn address
    # and manually increment the sender's nonce in the state
    burn_tx = {
        'transaction_id': str(uuid.uuid4()), 'sender': sender, 'recipient': "0x000000000000000000000000000000000000dEaD", 'amount': amount,
        'nonce': account_state['nonce'], 'type': 'burn', 'fee': 0.0, 'timestamp': time.time()
    }
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
    app.run(host='0.0.0.0', port=args.port, debug=False)
