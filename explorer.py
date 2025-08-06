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

# --- App Setup ---
app = Flask(__name__)
CORS(app)

# =============================================================================
# API Helper
# =============================================================================

def proxy_request(endpoint):
    """A helper to forward requests to the core node, including query params."""
    try:
        response = requests.get(f"{BUNKNET_NODE_URL}{endpoint}", params=request.args)
        # Pass through the status code and JSON response from the core node
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not connect to the BunkNet core node', 'details': str(e)}), 503

# =============================================================================
# Flask API Endpoints
# =============================================================================

# --- Passthrough Endpoints ---
# These endpoints are clean proxies that securely forward requests
# from the frontend to the core blockchain node.

@app.route('/api/status', methods=['GET'])
def get_status():
    """Gets the general status of the blockchain from the core node."""
    return proxy_request('/status')

@app.route('/api/blocks', methods=['GET'])
def get_blocks():
    """Gets a list of blocks, with optional pagination."""
    return proxy_request('/get_chain')

@app.route('/api/block/<identifier>', methods=['GET'])
def get_block(identifier):
    """Gets a single block by its index or hash."""
    return proxy_request(f'/get_block/{identifier}')
    
@app.route('/api/address/<address>', methods=['GET'])
def get_address_info(address):
    """Gets full details for a single address (balance, nonce, txs)."""
    return proxy_request(f'/address/{address}')

@app.route('/api/transaction/<tx_id>', methods=['GET'])
def get_transaction(tx_id):
    """Gets details for a single transaction by its ID."""
    return proxy_request(f'/transaction/{tx_id}')

@app.route('/api/get_mempool', methods=['GET'])
def get_mempool():
    """Gets the list of pending transactions."""
    return proxy_request('/get_mempool')

@app.route('/api/labels', methods=['GET'])
def get_labels():
    """Gets the map of known addresses and their labels."""
    # This endpoint can remain on the explorer if you want caching,
    # but for simplicity, proxying is cleaner.
    return proxy_request('/labels')

# Note: In a real public explorer, endpoints that change the state of the blockchain
# like /new_transaction or /mine_block would be removed for security.
# They are kept here for our project's educational and testing purposes.

@app.route('/api/new_transaction', methods=['POST'])
def new_transaction():
    """Forwards a new transaction to the core node's mempool."""
    try:
        response = requests.post(f"{BUNKNET_NODE_URL}/new_transaction", json=request.get_json())
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not connect to the BunkNet core node', 'details': str(e)}), 503

@app.route('/api/mine_block', methods=['GET'])
def mine():
    """Allows triggering the mining of a new block for demonstration."""
    return proxy_request('/mine_block')


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=7000, type=int, help='port to listen on')
    args = parser.parse_args()
    
    # The explorer BFF doesn't need to do anything at startup anymore,
    # as all logic is handled by the core node.
    app.run(host='0.0.0.0', port=args.port, debug=False)
  
