import datetime
import hashlib
import json
import uuid
from os import environ

from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING

# --- App & DB Setup ---
app = Flask(__name__)
# This allows the frontend explorer to make requests to the API
CORS(app)

# It's better to use environment variables for sensitive data
MONGO_URI = environ.get('BUNKNET_MONGO_URI', 'mongodb://localhost:27017/')
ADMIN_SECRET_KEY = environ.get('BUNKNET_ADMIN_KEY', 'bunknet_super_admin_key')

client = MongoClient(MONGO_URI)
db = client["bunknet"]
blocks_col = db["blocks"]
mempool_col = db["mempool"] # Using a dedicated collection for pending transactions
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
    # Using json.dumps with a default serializer is a robust way to handle this
    return json.loads(json.dumps(data, default=json_serial))


# --- Core Blockchain Logic (Now Stateless) ---

class Blockchain:
    def __init__(self):
        """
        Initializes the Blockchain. If the DB is empty, it creates the Genesis Block.
        The class itself is stateless; it always queries the DB for the current state.
        """
        if blocks_col.count_documents({}) == 0:
            # Create the genesis block if the chain is empty
            self.create_block(proof=1, previous_hash='0', transactions=[])

    def create_block(self, proof, previous_hash, transactions):
        """Creates a new block and saves it to the database."""
        last_block = self.get_previous_block()
        index = last_block['index'] + 1 if last_block else 1
        
        block = {
            'index': index,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp(),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': transactions
        }
        # The hash must be calculated *after* all other fields are set
        block['hash'] = self.hash(block)
        blocks_col.insert_one(block)
        return block

    def get_previous_block(self):
        """Retrieves the most recent block from the database."""
        return blocks_col.find_one(sort=[("index", DESCENDING)])

    def proof_of_work(self, previous_proof):
        """
        Simple Proof of Work Algorithm:
         - Find a number 'proof' such that hash(proof^2 - previous_proof^2) contains leading 4 zeroes
        """
        new_proof = 1
        while True:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                return new_proof
            new_proof += 1

    @staticmethod
    def hash(block):
        """Creates a SHA-256 hash of a Block."""
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        # A copy is made to avoid modifying the original block dict
        block_copy = block.copy()
        # The block's own hash can't be part of the data used to create the hash
        block_copy.pop('hash', None)
        block_string = json.dumps(block_copy, sort_keys=True, default=json_serial).encode()
        return hashlib.sha256(block_string).hexdigest()

    def add_transaction_to_mempool(self, sender, recipient, amount, tx_type="transfer"):
        """Adds a new transaction to the mempool for processing."""
        transaction = {
            'transaction_id': str(uuid.uuid4()),
            'sender': sender,
            'recipient': recipient,
            'amount': float(amount),
            'type': tx_type,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()
        }
        mempool_col.insert_one(transaction)
        # Return the transaction so the caller has the ID
        return transaction

    def get_balance(self, address):
        """Calculates the balance of an address by aggregating transactions from the blockchain."""
        pipeline = [
            # Unwind the transactions array to process each transaction individually
            {"$unwind": "$transactions"},
            # Match transactions where the address is either the sender or recipient
            {"$match": {"$or": [{"transactions.sender": address}, {"transactions.recipient": address}]}},
            # Group by sender/recipient and calculate total sent and received
            {"$group": {
                "_id": None,
                "total_sent": {"$sum": {
                    "$cond": [{"$eq": ["$transactions.sender", address]}, "$transactions.amount", 0]
                }},
                "total_received": {"$sum": {
                    "$cond": [{"$eq": ["$transactions.recipient", address]}, "$transactions.amount", 0]
                }}
            }}
        ]
        result = list(blocks_col.aggregate(pipeline))
        if not result:
            return 0.0
        
        totals = result[0]
        balance = totals.get('total_received', 0) - totals.get('total_sent', 0)
        return balance

    def is_chain_valid(self):
        """
        Determines if the blockchain is valid by checking hashes and proofs.
        This is an expensive operation and should be used sparingly.
        """
        chain = list(blocks_col.find(sort=[("index", 1)]))
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            # 1. Check if the previous_hash field is correct
            if block['previous_hash'] != self.hash(previous_block):
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


# --- API Endpoints ---

blockchain = Blockchain()

@app.route('/', methods=['GET'])
def home():
    log_fingerprint('home', request)
    return jsonify({
        "message": "Welcome to the BunkNet Blockchain API",
        "currentTime": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

@app.route('/mine_block', methods=['GET'])
def mine_block():
    """Mines a new block, includes a reward, and adds pending transactions."""
    log_fingerprint('mine_block', request)
    
    # Proof of Work
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    
    # Get all transactions from mempool and add the mining reward
    pending_transactions = list(mempool_col.find({}))
    # Clean up the _id field from MongoDB
    for tx in pending_transactions:
        tx.pop('_id', None)
        
    pending_transactions.append({
        'transaction_id': str(uuid.uuid4()),
        'sender': '0', # '0' or 'Network' for reward sender
        'recipient': 'Miner', # Can be a specific miner's address
        'amount': 1.0,
        'type': 'reward',
        'timestamp': datetime.datetime.now(datetime.timezone.utc).timestamp()
    })
    
    # Create the new block
    block = blockchain.create_block(proof, previous_hash, pending_transactions)
    
    # Clear the mempool now that transactions are confirmed
    mempool_col.delete_many({})
    
    response = {'message': 'Congratulations, you just mined a block!', 'block': prepare_json_response(block)}
    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    """Adds a transaction to the mempool."""
    log_fingerprint('add_transaction', request)
    values = request.get_json()
    required = ['sender', 'recipient', 'amount']
    if not all(key in values for key in required):
        return 'Missing values', 400
    
    transaction = blockchain.add_transaction_to_mempool(
        sender=values['sender'],
        recipient=values['recipient'],
        amount=values['amount']
    )
    response = {'message': f'Transaction with ID {transaction["transaction_id"]} added to the mempool.'}
    return jsonify(response), 201
    
# --- Explorer-Specific Endpoints ---

@app.route('/get_chain', methods=['GET'])
def get_chain():
    """Returns the entire blockchain."""
    log_fingerprint('get_chain', request)
    chain = list(blocks_col.find(sort=[("index", 1)]))
    response = {'chain': prepare_json_response(chain), 'length': len(chain)}
    return jsonify(response), 200

@app.route('/get_transaction/<txid>', methods=['GET'])
def get_transaction(txid):
    """Gets a single transaction by its ID from the blockchain."""
    log_fingerprint('get_transaction', request)
    # Search for the transaction within the 'transactions' array of all blocks
    block_containing_tx = blocks_col.find_one({"transactions.transaction_id": txid})
    if block_containing_tx:
        # Find the specific transaction from the array
        tx = next((tx for tx in block_containing_tx['transactions'] if tx['transaction_id'] == txid), None)
        if tx:
            return jsonify({"transaction": prepare_json_response(tx)}), 200
    return jsonify({'error': 'Transaction not found'}), 404
    
@app.route('/get_transactions', methods=['GET'])
def get_transactions_for_address():
    """Gets all transactions for a given address from a query parameter."""
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Address query parameter is required"}), 400
    
    log_fingerprint('get_transactions_for_address', request)
    pipeline = [
        {"$unwind": "$transactions"},
        {"$match": {"$or": [{"transactions.sender": address}, {"transactions.recipient": address}]}},
        {"$replaceRoot": {"newRoot": "$transactions"}} # Elevate the transaction doc to the top level
    ]
    transactions = list(blocks_col.aggregate(pipeline))
    return jsonify({"transactions": prepare_json_response(transactions)}), 200

@app.route('/get_balance', methods=['GET'])
def get_balance():
    """Gets the balance for an address from a query parameter."""
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Address query parameter is required"}), 400
        
    log_fingerprint('get_balance', request)
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/is_valid', methods=['GET'])
def is_valid():
    """Checks if the entire blockchain is valid."""
    log_fingerprint('is_valid', request)
    valid = blockchain.is_chain_valid()
    if valid:
        return jsonify({'message': 'The blockchain is valid.'}), 200
    else:
        return jsonify({'message': 'The blockchain is NOT valid.'}), 500

# --- Admin Endpoints ---

@app.route('/mint', methods=['POST'])
def mint_tokens():
    """Admin-only: Mints new tokens to an address."""
    log_fingerprint('mint', request)
    data = request.get_json()
    if data.get('admin_key') != ADMIN_SECRET_KEY:
        return 'Unauthorized', 403
    
    required = ['recipient', 'amount']
    if not all(k in data for k in required):
        return 'Missing fields for minting', 400
        
    tx = blockchain.add_transaction_to_mempool(
        sender='BunkNet Mint',
        recipient=data['recipient'],
        amount=data['amount'],
        tx_type='mint'
    )
    return jsonify({'message': f'{data["amount"]} $BUNK will be minted to {data["recipient"]}', 'transaction': prepare_json_response(tx)}), 201


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
