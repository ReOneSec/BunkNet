import os
import requests
from argparse import ArgumentParser
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()
# The URL of your main blockchain.py node
BUNKNET_NODE_URL = os.environ.get("BUNKNET_NODE_URL", "http://localhost:5000")

# --- App & Cache Setup ---
app = Flask(__name__)
CORS(app)

# A simple in-memory cache for address labels to reduce API calls
ADDRESS_LABELS_CACHE = {}

def update_labels_cache():
    """Fetches all labels from the core node and caches them."""
    global ADDRESS_LABELS_CACHE
    try:
        response = requests.get(f"{BUNKNET_NODE_URL}/labels")
        if response.status_code == 200:
            ADDRESS_LABELS_CACHE = response.json()
            print(f"✅ Successfully cached {len(ADDRESS_LABELS_CACHE)} address labels.")
        else:
            print("⚠️ Could not fetch address labels from the core node.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to core node to fetch labels: {e}")

# --- API Helper ---
def proxy_request(method, endpoint, params=None, json_data=None):
    """A helper to forward requests to the core node."""
    try:
        response = requests.request(
            method, f"{BUNKNET_NODE_URL}{endpoint}", params=params, json=json_data
        )
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not connect to the BunkNet core node', 'details': str(e)}), 503

# =============================================================================
# Flask API Endpoints
# =============================================================================

@app.route('/api/status', methods=['GET'])
def get_status():
    """Gets the general status of the blockchain from the core node."""
    try:
        chain_res = requests.get(f"{BUNKNET_NODE_URL}/get_chain", params={'limit': 1})
        mempool_res = requests.get(f"{BUNKNET_NODE_URL}/get_mempool")
        chain_res.raise_for_status(); mempool_res.raise_for_status()
        
        chain_data, mempool_data = chain_res.json(), mempool_res.json()
        last_block = chain_data['chain'][0] if chain_data.get('chain') else {}
        
        return jsonify({
            'chain_length': chain_data.get('length', 0),
            'last_block_hash': last_block.get('hash'),
            'last_block_index': last_block.get('index'),
            'pending_transactions': mempool_data.get('count', 0)
        })
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not connect to the BunkNet core node', 'details': str(e)}), 503

@app.route('/api/address/<address>', methods=['GET'])
def get_address_info(address):
    """Gets balance and history, and enriches it with a custom label if one exists."""
    try:
        balance_res = requests.get(f"{BUNKNET_NODE_URL}/get_balance", params={'address': address})
        txs_res = requests.get(f"{BUNKNET_NODE_URL}/get_transactions", params={'address': address})
        balance_res.raise_for_status(); txs_res.raise_for_status()
        
        balance_data, txs_data = balance_res.json(), txs_res.json()
        label = ADDRESS_LABELS_CACHE.get(address)
        
        return jsonify({
            'address': address,
            'label': label,
            'balance': balance_data.get('balance', 0),
            'transactions': txs_data.get('transactions', [])
        })
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not retrieve address info', 'details': str(e)}), 503
        
@app.route('/api/search/<query>', methods=['GET'])
def search(query):
    """Intelligently searches for a block or an address."""
    if not query or not query.strip():
        return jsonify({'error': 'Search query cannot be empty'}), 400
    
    # Try as a block first (more efficient)
    try:
        block_res = requests.get(f"{BUNKNET_NODE_URL}/get_block/{query}")
        if block_res.ok:
            return jsonify({'type': 'block', 'data': block_res.json()})
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Could not connect to core node'}), 503
        
    # If not a block, try as an address
    try:
        addr_res = requests.get(f"{BUNKNET_NODE_URL}/get_balance", params={'address': query})
        if addr_res.ok:
            # If it's a valid address, get the full enriched info
            full_addr_info_response, status_code = get_address_info(query)
            if status_code == 200:
                return jsonify({'type': 'address', 'data': full_addr_info_response.get_json()})
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Could not connect to core node'}), 503
    
    return jsonify({'error': 'No block or address found for the given query'}), 404

@app.route('/api/labels', methods=['GET'])
def get_labels():
    """Returns the cached address labels. Refreshes the cache on each call."""
    update_labels_cache()
    return jsonify(ADDRESS_LABELS_CACHE)

# --- Passthrough Endpoints ---
# These endpoints simply forward the request to the core node.
@app.route('/api/blocks', methods=['GET'])
def get_blocks():
    return proxy_request('GET', '/get_chain', params=request.args)

@app.route('/api/block/<identifier>', methods=['GET'])
def get_block(identifier):
    return proxy_request('GET', f'/get_block/{identifier}')

@app.route('/api/mempool', methods=['GET'])
def get_mempool():
    return proxy_request('GET', '/get_mempool')

@app.route('/api/new_transaction', methods=['POST'])
def new_transaction():
    return proxy_request('POST', '/add_transaction', json_data=request.get_json())

@app.route('/api/mine', methods=['GET'])
def mine():
    # Note: In a real public explorer, this endpoint would likely be removed for security.
    # It is kept here for our project's testing and demonstration purposes.
    return proxy_request('GET', '/unknown_block') #unknown is triggered as main but not, for security 

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=7000, type=int, help='port to listen on')
    args = parser.parse_args()
    
    # Load labels at startup
    update_labels_cache()
    
    app.run(host='0.0.0.0', port=args.port, debug=True)
      
