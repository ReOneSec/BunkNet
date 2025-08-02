# BunkNet

BunkNet: A Functional Proof-of-Work Blockchain 🌐
Welcome to BunkNet, a complete blockchain ecosystem built from the ground up. This project is a practical and educational implementation of the core principles that power cryptocurrencies. It features a decentralized P2P network, a native token ($BUNK) with a defined monetary policy, and a full suite of tools including a secure web wallet, a block explorer, and a CLI.
## Live Demo (Testnet)
 * Block Explorer: http://explorer.yourdomain.com
 * Web Wallet: http://wallet.yourdomain.com
 * Faucet: http://faucet.yourdomain.com
(Note: Replace with your actual hosted URLs.)
## Features
 * Decentralized P2P Network: Multiple nodes can connect, sync, and achieve consensus.
 * Proof-of-Work Consensus: Uses a simple but effective PoW algorithm to secure the network.
 * Native Cryptocurrency ($BUNK): Features a native token with transaction fees and a block reward halving schedule.
 * Cryptographic Security: All transactions are secured and verified with ECDSA signatures.
 * Secure Web Wallet: A full-featured, client-side wallet with encrypted, persistent login.
 * CLI Wallet: A powerful command-line interface for developers and power users.
 * Block Explorer: A responsive SPA to view all on-chain activity in real-time.
 * Automated Faucet: Provides free test $BUNK to new users for easy onboarding.
## Architecture Overview
BunkNet operates on a three-tiered architecture to separate concerns and improve scalability.
User ↔️ [Frontend Apps] ↔️ [Explorer BFF API] ↔️ [Core Blockchain Node] ↔️ [MongoDB]
 * Frontend Apps: The Web Wallet, Explorer, and Faucet (static HTML, CSS, JS).
 * Explorer BFF API (explorer.py): A smart middle-layer that simplifies API calls for the frontends.
 * Core Blockchain Node (blockchain.py): The main server that handles all blockchain logic, P2P communication, and consensus.
 * MongoDB: The database that provides persistent storage for the blockchain data.
## Getting Started (For Testers)
Want to try out BunkNet? It's easy to get started on the testnet.
 * Get Test $BUNK: Go to the Faucet website, paste your BunkNet address, and receive some free test tokens.
 * Create a Wallet: Visit the Web Wallet site, create a new wallet, and securely save your 12-word seed phrase.
 * Explore: Use the Block Explorer to see your faucet transaction confirm on the blockchain. You can now send and receive $BUNK with other testers!
## Running the Project Locally (For Developers)
### Prerequisites
 * Python 3.10+
 * pip and virtualenv
 * MongoDB running on its default port (27017)
### Installation & Setup
 * Clone the repository:
   git clone https://github.com/YourUsername/BunkNet.git
cd BunkNet

 * Set up a virtual environment and install dependencies:
   python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

 * Configure your environment:
   * Copy the example .env file: cp .env.example .env
   * Edit the .env file and set your BUNKNET_MINER_ADDRESS. You can create one using the CLI Wallet.
### Running the Services
 * Start the Core Blockchain Node:
   python3 blockchain.py --port 5000

 * Start the Explorer BFF (in a new terminal):
   python3 explorer.py --port 7000

 * Use the Frontend Apps:
   * Open the explorer/index.html and web-wallet/wallet.html files directly in your browser.
   * Ensure the API URLs in the .js files are pointing to http://localhost:7000.
## Technical Analysis of the BunkNet Ecosystem
Core Blockchain Architecture
 * Consensus Mechanism: Proof-of-Work (PoW). A simple but effective algorithm requires computational effort to mine new blocks, securing the chain.
 * Decentralization: A P2P networking layer allows multiple nodes to connect and sync with each other. The network achieves consensus using the Nakamoto Consensus rule ("longest valid chain").
 * Security: All transactions are secured with ECDSA (Elliptic Curve Digital Signature Algorithm). The server verifies every signature, ensuring that only the owner of a private key can authorize spending from their address.
 * Tokenomics:
   * Native Token: $BUNK.
   * Block Reward: The reward started at 50 $BUNK per block.
   * Monetary Policy: A halving schedule is implemented, cutting the block reward in half every 210,000 blocks to create digital scarcity.
   * Transaction Fees: Miners collect fees attached to transactions, providing a long-term incentive to secure the network.
 * Persistence: The blockchain, memory pool, and other state data are stored in a MongoDB database, ensuring data integrity and persistence.
Ecosystem Components
 * Explorer Backend (BFF): A dedicated Python server (explorer.py) that acts as a "Backend-for-Frontend." It provides a simplified and powerful API for the user-facing applications, including a unified search function.
 * Block Explorer: A responsive, modern Single Page Application (SPA) that provides a real-time view of the blockchain's activity, including blocks, transactions, and address balances.
 * Web Wallet: A full-featured, secure web application for end-users.
   * Security: A fully client-side wallet where private keys never leave the browser.
   * Persistent Login: Uses password-based AES encryption to securely store the user's seed phrase in local storage, allowing for easy "unlocking" of the wallet.
   * Features: Wallet creation (BIP39 seed phrase), import, sending/receiving $BUNK, an address book, and a settings panel.
 * CLI Wallet: A powerful command-line tool (wallet.py) for developers and power users. It supports all wallet functions, including generation, import, balance checks, sending transactions, and viewing the seed phrase for backup.
 * Faucet: An automated web page and API endpoint that dispenses a small amount of free $BUNK to new users, with rate-limiting to prevent abuse.
## CLI Wallet Usage
The CLI wallet (wallet.py) provides a powerful interface for managing your funds.
 * Create a new wallet:
   python3 wallet.py generate

 * Get your public address:
   python3 wallet.py address

 * Check your balance:
   python3 wallet.py balance

 * Send $BUNK:
   python3 wallet.py send --to RECIPIENT_ADDRESS --amount 0.5 --fee 0.01

 * View your seed phrase:
   python3 wallet.py backup

## Future Roadmap
 * Telegram Bot Wallet: A fully integrated wallet inside the Telegram app.
 * Smart Contract Layer: An execution engine to allow for decentralized applications (dApps).
 * Proof-of-Stake: A potential future migration to a more energy-efficient consensus mechanism.
## License
Distributed under the Apache 2.0 License. See LICENSE for more information.
