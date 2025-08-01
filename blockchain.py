from flask import Flask, jsonify, request
import datetime
import hashlib
import json

app = Flask(__name__)

# Define your admin secret key
ADMIN_SECRET_KEY = "bunknet_super_admin_key"  # Change this before production

class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_op = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_op[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount
        })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_op = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_op[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

blockchain = Blockchain()

@app.route('/', methods=['GET'])
def home():
    return "Welcome to BunkNet Blockchain API with $BUNK Token"

@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(sender='Network', receiver='Miner', amount=1)
    block = blockchain.create_block(proof, previous_hash)
    return jsonify({
        'message': 'Block mined successfully!',
        'block': block
    }), 200

@app.route('/get_chain', methods=['GET'])
def get_chain():
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }), 200

@app.route('/is_valid', methods=['GET'])
def is_valid():
    valid = blockchain.is_chain_valid(blockchain.chain)
    return jsonify({'valid': valid}), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json_data = request.get_json()
    required_fields = ['sender', 'receiver', 'amount']
    if not all(field in json_data for field in required_fields):
        return 'Missing transaction fields', 400
    index = blockchain.add_transaction(
        sender=json_data['sender'],
        receiver=json_data['receiver'],
        amount=json_data['amount']
    )
    return jsonify({'message': f'Transaction will be added to Block {index}'}), 201

@app.route('/mint', methods=['POST'])
def mint_tokens():
    json_data = request.get_json()
    required_fields = ['receiver', 'amount', 'admin_key']
    if not all(field in json_data for field in required_fields):
        return 'Missing fields', 400
    if json_data['admin_key'] != ADMIN_SECRET_KEY:
        return 'Unauthorized', 403
    receiver = json_data['receiver']
    amount = json_data['amount']
    index = blockchain.add_transaction(sender='BunkNet', receiver=receiver, amount=amount)
    return jsonify({'message': f'{amount} $BUNK minted to {receiver}', 'block': index}), 201

@app.route('/burn', methods=['POST'])
def burn_tokens():
    json_data = request.get_json()
    required_fields = ['from', 'amount', 'admin_key']
    if not all(field in json_data for field in required_fields):
        return 'Missing fields', 400
    if json_data['admin_key'] != ADMIN_SECRET_KEY:
        return 'Unauthorized', 403
    sender = json_data['from']
    amount = json_data['amount']
    index = blockchain.add_transaction(sender=sender, receiver='0x0', amount=amount)
    return jsonify({'message': f'{amount} $BUNK burned from {sender}', 'block': index}), 201

@app.route('/get_balance/<address>', methods=['GET'])
def get_balance(address):
    balance = 0
    for block in blockchain.chain:
        for tx in block['transactions']:
            if tx['receiver'] == address:
                balance += tx['amount']
            if tx['sender'] == address:
                balance -= tx['amount']
    return jsonify({'address': address, 'balance': balance}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
