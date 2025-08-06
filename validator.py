import os
import time
import requests
import logging
from dotenv import load_dotenv

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
load_dotenv()
NODE_URL = os.environ.get("BUNKNET_NODE_URL", "http://localhost:5000")
P2P_SECRET_KEY = os.environ.get("BUNKNET_P2P_KEY") # For secure communication
POLL_INTERVAL_SECONDS = 15
MAX_BACKOFF_SECONDS = 300 # Maximum wait time after repeated failures (5 minutes)

def run_validator():
    """
    Runs a continuous loop to check for pending transactions and mine blocks.
    Includes exponential backoff for connection errors.
    """
    logging.info("🚀 BunkNet Validator Started")
    logging.info(f"📡 Watching for transactions on node: {NODE_URL}")
    logging.info(f"🕒 Checking every {POLL_INTERVAL_SECONDS} seconds...")
    
    if not P2P_SECRET_KEY:
        logging.warning("⚠️ BUNKNET_P2P_KEY is not set. Communication with the node will be insecure.")
        
    print("-" * 50)

    backoff_time = POLL_INTERVAL_SECONDS

    while True:
        try:
            # Step 1: Check the mempool for pending transactions
            headers = {'X-P2P-Key': P2P_SECRET_KEY} if P2P_SECRET_KEY else {}
            mempool_response = requests.get(f"{NODE_URL}/get_mempool", headers=headers, timeout=10)
            mempool_response.raise_for_status()
            
            # If connection is successful, reset the backoff time
            backoff_time = POLL_INTERVAL_SECONDS
            
            mempool_data = mempool_response.json()
            pending_tx_count = mempool_data.get('count', 0)

            if pending_tx_count > 0:
                logging.info(f"✅ Found {pending_tx_count} pending transaction(s). Attempting to mine a new block...")

                # Step 2: If transactions exist, call the /mine_block endpoint
                mine_response = requests.get(f"{NODE_URL}/mine_block", headers=headers, timeout=60) # Longer timeout for mining
                mine_response.raise_for_status()
                
                mine_data = mine_response.json()
                new_block = mine_data.get('block', {})
                
                num_txs_in_block = len(new_block.get('transactions', [])) - 1 # -1 for the reward tx
                
                logging.info(f"🏆 SUCCESS! Mined new Block #{new_block.get('index')}")
                logging.info(f"   Hash: {new_block.get('hash', 'N/A')[:20]}...")
                logging.info(f"   Transactions Confirmed: {num_txs_in_block}")
                print("-" * 50)

            else:
                logging.info(f"😴 Mempool is empty. Waiting for new transactions...")

        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Error connecting to the blockchain node: {e}")
            logging.warning(f"   Retrying in {backoff_time} seconds...")
            time.sleep(backoff_time)
            # Increase backoff time for the next potential failure
            backoff_time = min(backoff_time * 2, MAX_BACKOFF_SECONDS)
            continue # Skip the normal sleep and retry immediately after backoff
        
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

        # Step 3: Wait for the next poll interval
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == '__main__':
    run_validator()
    
