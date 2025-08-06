import datetime
import hashlib
import json
import uuid
from os import environ
from urllib.parse import urlparse
from argparse import ArgumentParser
from functools import wraps

import binascii
import ecdsa
import requests
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from dotenv import load_dotenv
from mnemonic import Mnemonic

# Load environment variables from the .env file
load_dotenv()

# =============================================================================
# BunkNet Configuration
# =============================================================================
MONGO_URI = environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/')
ADMIN_SECRET_KEY = environ.get('BUNKNET_ADMIN_KEY', 'bunknet_super_admin_key')
MINER_ADDRESS = environ.get('BUNKNET_MINER_ADDRESS', 'bunknet_miner_rewards_address')
TREASURY_ADDRESS = environ.get('BUNKNET_TREASURY_ADDRESS')
FAUCET_SEED = environ.get('BUNKNET_FAUCET_SEED')

# --- Tokenomics Configuration ---
INITIAL_SUPPLY = 100000000.0
BASE_BLOCK_REWARD = 0
BURN_ADDRESS = "0x0000000000000000000000000000000000000BunkNetBurn"
FAUCET_DRIP_AMOUNT = 10
FAUCET_COOLDOWN_HOURS = 24

# =============================================================================
# Application & Database Setup
# =============================================================================
app = Flask(__name__)
CORS(app)

client = MongoClient(MONGO_URI)
db = client["bunknet_node"]
blocks_col = db["blocks"]
mempool_col = db["mempool"]
address_labels_col = db["address_labels"]
faucet_requests_col = db["faucet_requests"]

# --- Faucet Wallet Setup ---
if FAUCET_SEED:
    mnemo = Mnemonic("english")
    faucet_seed_bytes = mnemo.to_seed(FAUCET_SEED)
    faucet_private_key = ecdsa.SigningKey.from_string(faucet_seed_bytes[:32], curve=ecdsa.SECP256k1)
    FAUCET_PUBLIC_KEY = binascii.hexlify(faucet_private_key.get_verifying_key().to_string()).decode()
else:
    faucet_private_key, FAUCET_PUBLIC_KEY = None, None
    print("⚠️ WARNING: BUNKNET_FAUCET_SEED not found. Faucet will be disabled.")

# =============================================================================
# Utility & Decorators
# =============================================================================
def prepare_json_response(data):
    def json_serial(obj):
        if isinstance(obj, (datetime.datetime, ObjectId)): return str(obj)
        raise TypeError(f"Type {type(obj)} not serializable")
    return json.loads(json.dumps(data, default=json_serial))

def admin_required(f):
    """Decorator to protect admin endpoints with a secret key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_key = request.headers.get('X-Admin-Key')
        if not ADMIN_SECRET_KEY or auth_key != ADMIN_SECRET_KEY:
            return jsonify({'error': 'Unauthorized: Admin key required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# Core Blockchain Class
# =============================================================================
class Blockchain:
    def __init__(self):
        self.nodes = set()
        if blocks_col.count_documents({}) == 0:
            if not TREASURY_ADDRESS: raise ValueError("BUNKNET_TREASURY_ADDRESS must be set in .env")
            genesis_tx = {'transaction_id': str(uuid.uuid4()), 'sender': '0', 'recipient': TREASURY_ADDRESS, 'amount': INITIAL_SUPPLY, 'type': 'genesis_mint', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()}
            self.create_block(proof=1, previous_hash='0', transactions=[genesis_tx])

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc or parsed_url.path)

    @staticmethod
    def hash(block):
        block_copy = block.copy(); block_copy.pop('hash', None)
        block_string = json.dumps(block_copy, sort_keys=True, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def is_chain_valid(chain):
        previous_block = chain[0]
        for i in range(1, len(chain)):
            block = chain[i]
            if block['previous_hash'] != Blockchain.hash(previous_block): return False
            proof = block['proof']; previous_proof = previous_block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if not hash_operation.startswith('0000'): return False
            previous_block = block
        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain, max_length = None, blocks_col.count_documents({})
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/get_chain', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data['length'] > max_length and self.is_chain_valid(data['chain']):
                        max_length, new_chain = data['length'], data['chain']
            except requests.exceptions.RequestException: continue
        if new_chain:
            blocks_col.delete_many({}); blocks_col.insert_many(new_chain)
            return True
        return False

    def create_block(self, proof, previous_hash, transactions):
        last_block = self.get_previous_block()
        index = last_block['index'] + 1 if last_block else 1
        block = {'index': index, 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(), 'proof': proof, 'previous_hash': previous_hash, 'transactions': transactions}
        block['hash'] = self.hash(block)
        blocks_col.insert_one(block)
        return block

    def get_previous_block(self): return blocks_col.find_one(sort=[("index", DESCENDING)])

    def proof_of_work(self, previous_proof):
        new_proof = 1
        while True:
            hash_op = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_op.startswith('0000'): return new_proof
            new_proof += 1

    @staticmethod
    def verify_signature(public_key_hex, signature_hex, transaction_data):
        try:
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key_hex), curve=ecdsa.SECP256k1)
            tx_hash = hashlib.sha256(json.dumps(transaction_data, sort_keys=True).encode()).digest()
            return vk.verify(binascii.unhexlify(signature_hex), tx_hash)
        except Exception: return False

    def get_balance(self, address):
        pipeline = [{"$unwind": "$transactions"}, {"$match": {"$or": [{"transactions.sender": address}, {"transactions.recipient": address}]}}, {"$group": {"_id": None, "total_received": {"$sum": {"$cond": [{"$eq": ["$transactions.recipient", address]}, "$transactions.amount", 0]}}, "total_sent": {"$sum": {"$cond": [{"$eq": ["$transactions.sender", address]}, "$transactions.amount", 0]}}, "total_fees_paid": {"$sum": {"$cond": [{"$eq": ["$transactions.sender", address]}, {"$ifNull": ["$transactions.fee", 0]}, 0]}}}}]
        result = list(blocks_col.aggregate(pipeline))
        if not result: return 0.0
        totals = result[0]
        return totals.get('total_received', 0) - totals.get('total_sent', 0) - totals.get('total_fees_paid', 0)

    def add_transaction_to_mempool(self, sender, recipient, amount, fee, signature, public_key):
        amount, fee = float(amount), float(fee)
        if self.get_balance(sender) < (amount + fee): return {'error': 'Insufficient funds'}
        tx_data = {'sender': sender, 'recipient': recipient, 'amount': amount, 'fee': fee}
        if not self.verify_signature(public_key, signature, tx_data): return {'error': 'Invalid signature.'}
        full_tx = {**tx_data, 'transaction_id': str(uuid.uuid4()), 'type': 'transfer', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(), 'signature': signature, 'public_key': public_key}
        mempool_col.insert_one(full_tx)
        return full_tx

# =============================================================================
# Flask API Endpoints
# =============================================================================
blockchain = Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    prev_block = blockchain.get_previous_block()
    proof = blockchain.proof_of_work(prev_block['proof'])
    pending_txs = list(mempool_col.find({}, {'_id': 0}))
    total_fees = sum(tx.get('fee', 0) for tx in pending_txs)
    reward_tx = {'transaction_id': str(uuid.uuid4()), 'sender': '0', 'recipient': MINER_ADDRESS, 'amount': BASE_BLOCK_REWARD + total_fees, 'type': 'reward', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()}
    block = blockchain.create_block(proof, blockchain.hash(prev_block), pending_txs + [reward_tx])
    mempool_col.delete_many({})
    return jsonify({'message': 'New Block Forged', 'block': prepare_json_response(block)}), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    values = request.get_json(); required = ['sender', 'recipient', 'amount', 'fee', 'signature', 'public_key']
    if not all(key in values for key in required): return jsonify({'error': 'Missing values'}), 400
    if values['sender'] != values['public_key']: return jsonify({'error': 'Sender does not match public key'}), 400
    result = blockchain.add_transaction_to_mempool(**values)
    if 'error' in result: return jsonify(result), 400
    return jsonify({'message': f'Transaction {result["transaction_id"]} added.'}), 201

@app.route('/get_chain', methods=['GET'])
def get_chain():
    page, limit = int(request.args.get('page', 1)), int(request.args.get('limit', 0))
    query = blocks_col.find(sort=[("index", DESCENDING)])
    total = blocks_col.count_documents({})
    if limit > 0: query = query.skip((page - 1) * limit).limit(limit)
    return jsonify({'chain': prepare_json_response(list(query)), 'length': total, 'page': page, 'limit': limit}), 200

@app.route('/get_block/<identifier>', methods=['GET'])
def get_block(identifier):
    try: block = blocks_col.find_one({'index': int(identifier)})
    except ValueError: block = blocks_col.find_one({'hash': identifier})
    if block: return jsonify(prepare_json_response(block)), 200
    return jsonify({'error': 'Block not found'}), 404

@app.route('/get_mempool', methods=['GET'])
def get_mempool():
    mempool = list(mempool_col.find({}, {'_id': 0}))
    return jsonify({"mempool": mempool, "count": len(mempool)}), 200
    
@app.route('/get_balance', methods=['GET'])
def get_balance_endpoint():
    address = request.args.get('address')
    if not address: return jsonify({"error": "Address query parameter is required"}), 400
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/get_transactions', methods=['GET'])
def get_transactions_for_address():
    address = request.args.get('address')
    if not address: return jsonify({"error": "Address query parameter is required"}), 400
    
    # MODIFIED: This pipeline now includes the block_index in each transaction
    pipeline = [
        {"$unwind": "$transactions"},
        {"$match": {"$or": [{"transactions.sender": address}, {"transactions.recipient": address}]}},
        {
            "$replaceRoot": {
                "newRoot": {
                    "$mergeObjects": ["$transactions", {"block_index": "$index"}]
                }
            }
        }
    ]
    transactions = list(blocks_col.aggregate(pipeline))
    return jsonify({"transactions": prepare_json_response(transactions)}), 200
    
@app.route('/faucet/drip', methods=['POST'])
def faucet_drip():
    if not faucet_private_key: return jsonify({'error': 'Faucet is not configured.'}), 501
    recipient = request.get_json().get('recipient')
    if not recipient: return jsonify({'error': 'Recipient address is required.'}), 400
    cooldown = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=FAUCET_COOLDOWN_HOURS)
    if faucet_requests_col.find_one({"address": recipient, "timestamp": {"$gte": cooldown}}):
        return jsonify({'error': f'Address has received funds within {FAUCET_COOLDOWN_HOURS} hours.'}), 429
    if blockchain.get_balance(FAUCET_PUBLIC_KEY) < FAUCET_DRIP_AMOUNT: return jsonify({'error': 'Faucet is empty.'}), 503
    tx_data = {'sender': FAUCET_PUBLIC_KEY, 'recipient': recipient, 'amount': FAUCET_DRIP_AMOUNT, 'fee': 0.0}
    tx_hash = hashlib.sha256(json.dumps(tx_data, sort_keys=True).encode()).digest()
    signature = binascii.hexlify(faucet_private_key.sign(tx_hash)).decode()
    result = blockchain.add_transaction_to_mempool(sender=FAUCET_PUBLIC_KEY, recipient=recipient, amount=FAUCET_DRIP_AMOUNT, fee=0.0, signature=signature, public_key=FAUCET_PUBLIC_KEY)
    if 'error' in result: return jsonify(result), 500
    faucet_requests_col.insert_one({"address": recipient, "timestamp": datetime.datetime.now(datetime.timezone.utc)})
    return jsonify({'message': f'Sent {FAUCET_DRIP_AMOUNT} $BUNK.', 'tx_id': result['transaction_id']}), 201

@app.route('/labels', methods=['GET'])
def get_labels():
    labels = list(address_labels_col.find({}, {'_id': 0}))
    label_map = {item['address']: item['label'] for item in labels}
    return jsonify(label_map), 200

# --- Admin Endpoints ---
@app.route('/admin/mint', methods=['POST'])
@admin_required
def admin_mint_tokens():
    values = request.get_json()
    recipient, amount = values.get('recipient'), float(values.get('amount', 0))
    if not recipient or amount <= 0: return jsonify({'error': 'Recipient and positive amount required'}), 400
    mint_tx = {'transaction_id': str(uuid.uuid4()), 'sender': '0', 'recipient': recipient, 'amount': amount, 'type': 'admin_mint', 'fee': 0, 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()}
    mempool_col.insert_one(mint_tx)
    return jsonify({'message': f'Mint transaction for {amount} $BUNK to {recipient} created.'}), 201

@app.route('/admin/burn', methods=['POST'])
@admin_required
def admin_burn_tokens():
    values = request.get_json()
    amount = float(values.get('amount', 0))
    if amount <= 0: return jsonify({'error': 'Positive amount required'}), 400
    burn_tx = {'transaction_id': str(uuid.uuid4()), 'sender': TREASURY_ADDRESS, 'recipient': BURN_ADDRESS, 'amount': amount, 'type': 'burn', 'fee': 0, 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()}
    mempool_col.insert_one(burn_tx)
    return jsonify({'message': f'Burn transaction for {amount} $BUNK from Treasury created.'}), 201

@app.route('/admin/set_address_label', methods=['POST'])
@admin_required
def set_address_label():
    values = request.get_json()
    address, label = values.get('address'), values.get('label')
    if not address or not label: return jsonify({'error': 'Address and label are required'}), 400
    address_labels_col.update_one({'address': address}, {'$set': {'label': label}}, upsert=True)
    return jsonify({'message': f"Label '{label}' set for address {address[:10]}..."}), 200

# --- P2P Networking Endpoints ---
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    nodes = request.get_json().get('nodes')
    if nodes is None: return "Error: Please supply a valid list of nodes", 400
    for node in nodes: blockchain.add_node(node)
    return jsonify({'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    message = 'Our chain was replaced' if replaced else 'Our chain is authoritative'
    chain = list(blocks_col.find(sort=[("index", 1)]))
    return jsonify({'message': message, 'chain': prepare_json_response(chain)}), 200

if __name__ == '__main__':
    parser = ArgumentParser(); parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on'); args = parser.parse_args(); app.run(host='0.0.0.0', port=args.port, debug=True)
