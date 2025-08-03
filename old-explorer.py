import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

# --- App Configuration ---
app = Flask(__name__)
# Enable Cross-Origin Resource Sharing to allow your frontend to call this API
CORS(app)

# The address of your main blockchain node API
BLOCKCHAIN_API_URL = "http://localhost:5000"

# --- API Endpoints ---
# These endpoints act as a proxy/BFF to the main blockchain API

@app.route('/api/status', methods=['GET'])
def get_status():
    """
    Gets the general status of the blockchain by calling the main node.
    """
    try:
        response = requests.get(f"{BLOCKCHAIN_API_URL}/get_chain")
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        data = response.json()
        
        # Get pending transactions from the mempool
        mempool_response = requests.get(f"{BLOCKCHAIN_API_URL}/get_mempool")
        mempool_response.raise_for_status()
        mempool_data = mempool_response.json()
        
        return jsonify({
            'chain_length': data.get('length', 0),
            'last_block_hash': data['chain'][-1]['hash'] if data.get('chain') else None,
            'pending_transactions': len(mempool_data.get('mempool', []))
        })
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not connect to the blockchain node', 'details': str(e)}), 503

@app.route('/api/blocks', methods=['GET'])
def get_blocks():
    """Proxies the request to get all blocks from the blockchain node."""
    try:
        response = requests.get(f"{BLOCKCHAIN_API_URL}/get_chain")
        response.raise_for_status()
        return jsonify(response.json().get('chain', []))
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not fetch blocks', 'details': str(e)}), 503

@app.route('/api/block/<string:block_hash>', methods=['GET'])
def get_block_by_hash(block_hash):
    """
    Finds a specific block by its hash.
    This is more efficient than the frontend fetching the whole chain.
    """
    try:
        response = requests.get(f"{BLOCKCHAIN_API_URL}/get_chain")
        response.raise_for_status()
        chain = response.json().get('chain', [])
        
        # Search for the block in the returned chain
        for block in chain:
            if block['hash'] == block_hash:
                return jsonify(block), 200
        
        return jsonify({'error': 'Block not found'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not fetch chain data', 'details': str(e)}), 503

@app.route('/api/tx/<string:tx_id>', methods=['GET'])
def get_transaction_by_id(tx_id):
    """Proxies the request to get a specific transaction by its ID."""
    try:
        response = requests.get(f"{BLOCKCHAIN_API_URL}/get_transaction/{tx_id}")
        if response.status_code == 404:
            return jsonify({'error': 'Transaction not found'}), 404
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not fetch transaction', 'details': str(e)}), 503

@app.route('/api/address/<string:address>', methods=['GET'])
def get_address_info(address):
    """
    Combines balance and transaction history for an address from multiple backend calls.
    This is a core function of a Backend-for-Frontend.
    """
    try:
        # 1. Get balance
        balance_res = requests.get(f"{BLOCKCHAIN_API_URL}/get_balance", params={'address': address})
        balance_res.raise_for_status()
        balance_data = balance_res.json()
        
        # 2. Get transactions
        txs_res = requests.get(f"{BLOCKCHAIN_API_URL}/get_transactions", params={'address': address})
        txs_res.raise_for_status()
        txs_data = txs_res.json()
        
        # 3. Combine and return
        return jsonify({
            'address': address,
            'balance': balance_data.get('balance', 0),
            'transactions': txs_data.get('transactions', [])
        })
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not retrieve address info', 'details': str(e)}), 503
        
@app.route('/api/search/<string:query>', methods=['GET'])
def search(query):
    """
    A powerful search endpoint that intelligently checks if the query is a
    block hash, a transaction ID, or an address.
    """
    if not query or not query.strip():
        return jsonify({'error': 'Search query cannot be empty'}), 400

    # 1. Try as a block hash (hashes are typically 64 chars long)
    if len(query) == 64:
        block_res = requests.get(f"{BLOCKCHAIN_API_URL}/get_chain")
        if block_res.ok:
            for block in block_res.json().get('chain', []):
                if block['hash'] == query:
                    return jsonify({'type': 'block', 'data': block})

    # 2. Try as a transaction ID
    tx_res = requests.get(f"{BLOCKCHAIN_API_URL}/get_transaction/{query}")
    if tx_res.ok:
        return jsonify({'type': 'transaction', 'data': tx_res.json().get('transaction')})

    # 3. Try as an address
    addr_res = requests.get(f"{BLOCKCHAIN_API_URL}/get_balance", params={'address': query})
    if addr_res.ok and addr_res.json().get('balance') is not None:
         # If balance check is successful, fetch full address info
        full_addr_info_res = get_address_info(query)
        if full_addr_info_res.status_code == 200:
            return jsonify({'type': 'address', 'data': full_addr_info_res.get_json()})

    return jsonify({'error': 'No result found for the given query'}), 404


@app.route('/api/new_transaction', methods=['POST'])
def new_transaction():
    """Proxies the request to add a new transaction to the node's mempool."""
    data = request.get_json()
    if not data or not all(k in data for k in ['sender', 'recipient', 'amount']):
        return jsonify({'error': 'Missing required transaction fields'}), 400
    try:
        response = requests.post(f"{BLOCKCHAIN_API_URL}/add_transaction", json=data)
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to submit transaction', 'details': str(e)}), 503

@app.route('/api/mine', methods=['POST'])
def mine():
    """
    Sends a request to the main node to mine a new block.
    Note: The main node uses GET for /mine_block, but we keep POST here for semantic consistency.
    """
    try:
        response = requests.get(f"{BLOCKCHAIN_API_URL}/mine_block")
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to trigger mining', 'details': str(e)}), 503

if __name__ == '__main__':
    # It's recommended to run the explorer on a different port than the main node
    app.run(host='0.0.0.0', port=7000, debug=True)
