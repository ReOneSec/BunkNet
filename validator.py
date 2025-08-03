import os
import time
import requests
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()
NODE_URL = os.environ.get("BUNKNET_NODE_URL", "http://localhost:5000")
POLL_INTERVAL_SECONDS = 15 # Check for transactions every 15 seconds

def run_validator():
    """
    Runs a continuous loop to check for pending transactions and mine blocks.
    """
    print("🚀 BunkNet Validator Started")
    print(f"📡 Watching for transactions on node: {NODE_URL}")
    print(f"🕒 Checking every {POLL_INTERVAL_SECONDS} seconds...")
    print("-" * 40)

    while True:
        try:
            # Step 1: Check the mempool for pending transactions
            mempool_response = requests.get(f"{NODE_URL}/get_mempool")
            mempool_response.raise_for_status()
            
            mempool_data = mempool_response.json()
            pending_tx_count = mempool_data.get('count', 0)

            if pending_tx_count > 0:
                print(f"✅ Found {pending_tx_count} pending transaction(s). Attempting to mine a new block...")

                # Step 2: If transactions exist, call the /mine_block endpoint
                mine_response = requests.get(f"{NODE_URL}/mine_block")
                mine_response.raise_for_status()
                
                mine_data = mine_response.json()
                new_block = mine_data.get('block', {})
                
                # Parse the response to provide a nice summary
                num_txs_in_block = len(new_block.get('transactions', [])) - 1 # -1 for the reward tx
                
                print(f"🏆 SUCCESS! Mined new Block #{new_block.get('index')}")
                print(f"   Hash: {new_block.get('hash', 'N/A')[:20]}...")
                print(f"   Transactions Confirmed: {num_txs_in_block}")
                print("-" * 40)

            else:
                # If no transactions, just print a status update
                print(f"😴 Mempool is empty. Waiting for new transactions...")

        except requests.exceptions.RequestException as e:
            print(f"❌ Error connecting to the blockchain node: {e}")
            print("   Is your blockchain.py server running?")
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        # Step 3: Wait for the next poll interval
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == '__main__':
    run_validator()
  
