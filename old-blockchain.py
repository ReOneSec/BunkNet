import datetime
import hashlib
import json
import uuid
from os import environ
from urllib.parse import urlparse
from argparse import ArgumentParser

import binascii
import ecdsa
import requests
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# =============================================================================
# BunkNet Configuration
# =============================================================================
MONGO_URI = environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/')
ADMIN_SECRET_KEY = environ.get('BUNKNET_ADMIN_KEY', 'bunknet_super_admin_key')
MINER_ADDRESS = environ.get('BUNKNET_MINER_ADDRESS', 'bunknet_miner_rewards_address')

# --- Tokenomics Configuration ---
INITIAL_BLOCK_REWARD = 50.0
HALVING_INTERVAL = 210000  # Block reward halves every 210,000 blocks.

# =============================================================================
# Application & Database Setup
# =============================================================================
app = Flask(__name__)
CORS(app)

client = MongoClient(MONGO_URI)
db = client["bunknet_node"]
blocks_col = db["blocks"]
mempool_col = db["mempool"]
log_col = db["logs"]

# =============================================================================
# Utility Functions
# =============================================================================
def json_serial(obj):
    """Handles non-serializable types for JSON responses."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def prepare_json_response(data):
    """Prepares Python dicts for a clean JSON response."""
    return json.loads(json.dumps(data, default=json_serial))

# =============================================================================
# Core Blockchain Class
# =============================================================================
class Blockchain:
    def __init__(self):
        """Initializes the Blockchain and its node set, creates Genesis block if needed."""
        self.nodes = set()
        if blocks_col.count_documents({}) == 0:
            self.create_block(proof=1, previous_hash='0', transactions=[])

    def add_node(self, address):
        """Adds a new peer node to the network list."""
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc or parsed_url.path)

    @staticmethod
    def hash(block):
        """Creates a SHA-256 hash of a Block."""
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_string = json.dumps(block_copy, sort_keys=True, default=json_serial).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def is_chain_valid(chain):
        """Determines if a given blockchain is valid by checking all hashes and proofs."""
        previous_block = chain[0]
        for i in range(1, len(chain)):
            block = chain[i]
            if block['previous_hash'] != Blockchain.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            current_proof = block['proof']
            hash_operation = hashlib.sha256(str(current_proof**2 - previous_proof**2).encode()).hexdigest()
            if not hash_operation.startswith('0000'):
                return False
            previous_block = block
        return True

    def resolve_conflicts(self):
        """Consensus Algorithm: Replaces our chain with the longest valid chain in the network."""
        neighbours = self.nodes
        new_chain, max_length = None, blocks_col.count_documents({})

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/get_chain', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data['length'] > max_length and self.is_chain_valid(data['chain']):
                        max_length, new_chain = data['length'], data['chain']
            except requests.exceptions.RequestException:
                continue

        if new_chain:
            blocks_col.delete_many({})
            blocks_col.insert_many(new_chain)
            return True
        return False

    def create_block(self, proof, previous_hash, transactions):
        """Creates a new block and saves it to the database."""
        last_block = self.get_previous_block()
        index = last_block['index'] + 1 if last_block else 1
        block = {
            'index': index, 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(),
            'proof': proof, 'previous_hash': previous_hash, 'transactions': transactions
        }
        block['hash'] = self.hash(block)
        blocks_col.insert_one(block)
        return block

    def get_previous_block(self):
        """Retrieves the most recent block from the database."""
        return blocks_col.find_one(sort=[("index", DESCENDING)])

    def proof_of_work(self, previous_proof):
        """Simple Proof of Work: Find a number 'proof' that satisfies the condition."""
        new_proof = 1
        while True:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation.startswith('0000'):
                return new_proof
            new_proof += 1

    @staticmethod
    def verify_signature(public_key_hex, signature_hex, transaction_data):
        """Verifies a transaction's signature using ECDSA."""
        try:
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key_hex), curve=ecdsa.SECP256k1)
            tx_hash = hashlib.sha256(json.dumps(transaction_data, sort_keys=True).encode()).digest()
            return vk.verify(binascii.unhexlify(signature_hex), tx_hash)
        except Exception:
            return False

    def get_balance(self, address):
        """Calculates the balance for an address, accounting for sent amounts and fees."""
        pipeline = [
            {"$unwind": "$transactions"},
            {"$match": {"$or": [{"transactions.sender": address}, {"transactions.recipient": address}]}},
            {"$group": {
                "_id": None,
                "total_received": {"$sum": {"$cond": [{"$eq": ["$transactions.recipient", address]}, "$transactions.amount", 0]}},
                "total_sent": {"$sum": {"$cond": [{"$eq": ["$transactions.sender", address]}, "$transactions.amount", 0]}},
                "total_fees_paid": {"$sum": {"$cond": [{"$eq": ["$transactions.sender", address]}, {"$ifNull": ["$transactions.fee", 0]}, 0]}}
            }}
        ]
        result = list(blocks_col.aggregate(pipeline))
        if not result: return 0.0
        totals = result[0]
        return totals.get('total_received', 0) - totals.get('total_sent', 0) - totals.get('total_fees_paid', 0)

    def add_transaction_to_mempool(self, sender, recipient, amount, fee, signature, public_key):
        """Validates a transaction and adds it to the memory pool."""
        amount, fee = float(amount), float(fee)
        if self.get_balance(sender) < (amount + fee):
            return {'error': 'Insufficient funds to cover amount + fee.'}
        
        transaction_data = {'sender': sender, 'recipient': recipient, 'amount': amount, 'fee': fee}
        if not self.verify_signature(public_key, signature, transaction_data):
            return {'error': 'Invalid signature.'}

        full_transaction = {**transaction_data, 'transaction_id': str(uuid.uuid4()), 'type': 'transfer', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(), 'signature': signature, 'public_key': public_key}
        mempool_col.insert_one(full_transaction)
        return full_transaction

    def get_current_block_reward(self, height):
        """Calculates the block reward based on the halving schedule."""
        halvings = height // HALVING_INTERVAL
        return INITIAL_BLOCK_REWARD / (2**halvings)

# =============================================================================
# Flask API Endpoints
# =============================================================================
blockchain = Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    proof = blockchain.proof_of_work(previous_block['proof'])
    
    pending_transactions = list(mempool_col.find({}, {'_id': 0}))
    total_fees = sum(tx.get('fee', 0) for tx in pending_transactions)
    
    current_height = previous_block['index'] + 1 if previous_block else 1
    base_reward = blockchain.get_current_block_reward(current_height)
    
    reward_tx = {
        'transaction_id': str(uuid.uuid4()), 'sender': '0', 'recipient': MINER_ADDRESS,
        'amount': base_reward + total_fees, 'type': 'reward', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()
    }
    
    block = blockchain.create_block(proof, blockchain.hash(previous_block), pending_transactions + [reward_tx])
    mempool_col.delete_many({})
    
    return jsonify({'message': 'New Block Forged', 'block': prepare_json_response(block)}), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'fee', 'signature', 'public_key']
    if not all(key in values for key in required): return jsonify({'error': 'Missing values'}), 400
    if values['sender'] != values['public_key']: return jsonify({'error': 'Sender does not match public key'}), 400

    result = blockchain.add_transaction_to_mempool(**values)
    if 'error' in result: return jsonify(result), 400
    return jsonify({'message': f'Transaction {result["transaction_id"]} added to mempool.'}), 201
    
@app.route('/get_chain', methods=['GET'])
def get_chain():
    page, limit = int(request.args.get('page', 1)), int(request.args.get('limit', 0))
    query = blocks_col.find(sort=[("index", DESCENDING)])
    total = blocks_col.count_documents({})
    if limit > 0: query = query.skip((page - 1) * limit).limit(limit)
    return jsonify({'chain': prepare_json_response(list(query)), 'length': total, 'page': page, 'limit': limit}), 200

@app.route('/get_block/<identifier>', methods=['GET'])
def get_block(identifier):
    try:
        block = blocks_col.find_one({'index': int(identifier)})
    except ValueError:
        block = blocks_col.find_one({'hash': identifier})
    if block: return jsonify(prepare_json_response(block)), 200
    return jsonify({'error': 'Block not found'}), 404

@app.route('/get_mempool', methods=['GET'])
def get_mempool():
    mempool = list(mempool_col.find({}, {'_id': 0}))
    return jsonify({"mempool": mempool, "count": len(mempool)}), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    nodes = request.get_json().get('nodes')
    if nodes is None: return "Error: Please supply a valid list of nodes", 400
    for node in nodes:
        blockchain.add_node(node)
    return jsonify({'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    message = 'Our chain was replaced' if replaced else 'Our chain is authoritative'
    chain = list(blocks_col.find(sort=[("index", 1)])) # Fetch the current state of the chain after resolution
    return jsonify({'message': message, 'chain': prepare_json_response(chain)}), 200

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port, debug=True)
