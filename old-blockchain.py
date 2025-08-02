import datetime
import hashlib
import json
import uuid
from os import environ
from urllib.parse import urlparse

import binascii
import ecdsa
import requests
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING

# --- App & DB Setup ---
app = Flask(__name__)
CORS(app)

# --- Configuration ---
# Use environment variables for configuration
MONGO_URI = environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/')
ADMIN_SECRET_KEY = environ.get('BUNKNET_ADMIN_KEY', 'bunknet_super_admin_key')
# The address that will receive mining rewards.
MINER_ADDRESS = environ.get('BUNKNET_MINER_ADDRESS', 'bunknet_miner_rewards_address')

client = MongoClient(MONGO_URI)
db = client["bunknet_node"] # Use a unique DB for each node if running locally
blocks_col = db["blocks"]
mempool_col = db["mempool"]
log_col = db["logs"]

# --- Utility Functions ---

def log_fingerprint(route, req):
    """Logs request details to the database."""
    log_col.insert_one({
        'route': route,
        'ip': req.remote_addr,
        'headers': dict(req.headers),
        'time': datetime.datetime.now(datetime.timezone.utc)
    })

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def prepare_json_response(data):
    """Prepares data for JSON response by converting non-serializable types."""
    return json.loads(json.dumps(data, default=json_serial))

# --- Core Blockchain Logic (with Networking) ---

class Blockchain:
    def __init__(self):
        self.nodes = set()
        if blocks_col.count_documents({}) == 0:
            self.create_block(proof=1, previous_hash='0', transactions=[])

    def add_node(self, address):
        """Adds a new node to the list of nodes."""
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid node address')

    @staticmethod
    def hash(block):
        """Creates a SHA-256 hash of a Block."""
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_string = json.dumps(block_copy, sort_keys=True, default=json_serial).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def is_chain_valid(chain):
        """Determines if a given blockchain is valid."""
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            # 1. Check if the previous_hash field is correct
            if block['previous_hash'] != Blockchain.hash(previous_block):
                return False
            # 2. Check if the Proof of Work is valid
            previous_proof = previous_block['proof']
            current_proof = block['proof']
            hash_operation = hashlib.sha256(str(current_proof**2 - previous_proof**2).encode()).hexdigest()
            if not hash_operation.startswith('0000'):
                return False
            previous_block = block
            block_index += 1
        return True

    def resolve_conflicts(self):
        """
        This is our Consensus Algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """
        neighbours = self.nodes
        new_chain = None
        max_length = blocks_col.count_documents({})

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/get_chain')
                if response.status_code == 200:
                    data = response.json()
                    length = data['length']
                    chain = data['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.RequestException as e:
                print(f"Could not connect to node {node}: {e}")
                continue

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            # Completely replace our collection
            blocks_col.delete_many({})
            blocks_col.insert_many(new_chain)
            return True

        return False

    def create_block(self, proof, previous_hash, transactions):
        last_block = self.get_previous_block()
        index = last_block['index'] + 1 if last_block else 1
        block = {
            'index': index,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': transactions
        }
        block['hash'] = self.hash(block)
        blocks_col.insert_one(block)
        return block

    def get_previous_block(self):
        return blocks_col.find_one(sort=[("index", DESCENDING)])

    def proof_of_work(self, previous_proof):
        new_proof = 1
        while True:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                return new_proof
            new_proof += 1

    @staticmethod
    def verify_signature(public_key_hex, signature_hex, transaction_data):
        try:
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key_hex), curve=ecdsa.SECP256k1)
            tx_hash = hashlib.sha256(json.dumps(transaction_data, sort_keys=True).encode()).digest()
            return vk.verify(binascii.unhexlify(signature_hex), tx_hash)
        except Exception:
            return False

    def add_transaction_to_mempool(self, sender_address, recipient, amount, signature, public_key):
        transaction_data = {'sender': sender_address, 'recipient': recipient, 'amount': float(amount)}
        if not self.verify_signature(public_key, signature, transaction_data):
            return None
        full_transaction = {**transaction_data, 'transaction_id': str(uuid.uuid4()), 'type': 'transfer', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(), 'signature': signature, 'public_key': public_key}
        mempool_col.insert_one(full_transaction)
        return full_transaction


# --- API Endpoints ---
blockchain = Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    log_fingerprint('mine_block', request)
    previous_block = blockchain.get_previous_block()
    proof = blockchain.proof_of_work(previous_block['proof'])
    previous_hash = blockchain.hash(previous_block)
    
    pending_transactions = list(mempool_col.find({}, {'_id': 0}))
    pending_transactions.append({
        'transaction_id': str(uuid.uuid4()), 'sender': '0', 'recipient': MINER_ADDRESS,
        'amount': 1.0, 'type': 'reward', 'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()
    })
    
    block = blockchain.create_block(proof, previous_hash, pending_transactions)
    mempool_col.delete_many({})
    
    response = {'message': 'New Block Forged', 'block': prepare_json_response(block)}
    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    log_fingerprint('add_transaction', request)
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature', 'public_key']
    if not all(key in values for key in required):
        return jsonify({'error': 'Missing values for signed transaction'}), 400
    if values['sender'] != values['public_key']:
        return jsonify({'error': 'Sender address does not match public key'}), 400

    transaction = blockchain.add_transaction_to_mempool(
        sender_address=values['public_key'], recipient=values['recipient'],
        amount=values['amount'], signature=values['signature'], public_key=values['public_key']
    )
    if transaction is None: return jsonify({'error': 'Invalid transaction signature'}), 403
    return jsonify({'message': f'Transaction {transaction["transaction_id"]} added to mempool.'}), 201
    
@app.route('/get_chain', methods=['GET'])
def get_chain():
    """Returns the blockchain, with optional pagination."""
    log_fingerprint('get_chain', request)
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 0)) # 0 means no limit

    query = blocks_col.find(sort=[("index", DESCENDING)])
    total = blocks_col.count_documents({})

    if limit > 0:
        skip = (page - 1) * limit
        query = query.skip(skip).limit(limit)

    chain = list(query)
    response = {'chain': prepare_json_response(chain), 'length': total, 'page': page, 'limit': limit}
    return jsonify(response), 200

@app.route('/get_block/<identifier>', methods=['GET'])
def get_block(identifier):
    """Gets a single block by its index (height) or hash."""
    log_fingerprint('get_block', request)
    try:
        # Try to treat identifier as a number (index)
        index = int(identifier)
        block = blocks_col.find_one({'index': index})
    except ValueError:
        # If it's not a number, treat it as a hash
        block = blocks_col.find_one({'hash': identifier})
    
    if block:
        return jsonify(prepare_json_response(block)), 200
    else:
        return jsonify({'error': 'Block not found'}), 404

@app.route('/get_mempool', methods=['GET'])
def get_mempool():
    """Returns all transactions currently in the mempool."""
    log_fingerprint('get_mempool', request)
    mempool = list(mempool_col.find({}, {'_id': 0}))
    return jsonify({"mempool": mempool, "count": len(mempool)}), 200

# Other existing endpoints for balance, history, etc. remain the same and are assumed to be here...
# ... (add /get_balance, /get_transactions, etc. from previous versions if needed)

# --- Networking Endpoints ---

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.add_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {'message': 'Our chain was replaced', 'new_chain': prepare_json_response(list(blocks_col.find()))}
    else:
        response = {'message': 'Our chain is authoritative', 'chain': prepare_json_response(list(blocks_col.find()))}
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='0.0.0.0', port=port, debug=True)
